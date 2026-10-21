import {test, expect} from '@playwright/test';
import {spawn, ChildProcess} from 'node:child_process';
import {mkdtemp, mkdir, writeFile, readFile, rm, copyFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {resolve, join} from 'node:path';
const repo = resolve('../../..');
let dir:string, server:ChildProcess, url:string;
async function launch(effect="panic") {
  server=spawn(join(repo,'target/debug/cargo-sniff-test'),['--audit','gui','-e',effect],{cwd:dir,detached:process.platform!=="win32",env:{...process.env,SNIFF_TEST_AUDIT_NO_OPEN:'1'}});
  url=await new Promise<string>((resolve,reject)=>{let output='';const timeout=setTimeout(()=>reject(Error(output||'server launch timed out')),20000);server.stderr!.on('data',data=>{output+=data;const match=output.match(/Audit GUI: (http:\/\/[^\s]+)/);if(match){clearTimeout(timeout);resolve(match[1]);}});server.once('exit',code=>{clearTimeout(timeout);reject(Error(`server exited ${code}: ${output}`));});});
}
async function stop(){if(server?.exitCode===null){await new Promise<void>(resolve=>{server.once('exit',()=>resolve());if(process.platform==='win32')server.kill('SIGTERM');else process.kill(-server.pid!,'SIGTERM');});}}
test.beforeEach(async()=>{
  dir=await mkdtemp(join(tmpdir(),'sniff-audit-browser-'));await mkdir(join(dir,'src'));
  await writeFile(join(dir,'Cargo.toml'),'[package]\nname="audit-browser-fixture"\nversion="0.1.0"\nedition="2024"\n[workspace]\n');
  await copyFile(join(repo,'rust-toolchain.toml'),join(dir,'rust-toolchain.toml'));
  await writeFile(join(dir,'src/lib.rs'),'pub fn risky() {\n    panic!("intentional test panic");\n}\n');
  await launch();
});
test.afterEach(async()=>{await stop();if(dir)await rm(dir,{recursive:true,force:true,maxRetries:5,retryDelay:100});});
async function selectFinding(page:any){await page.goto(url);await expect(page.locator('.finding').first()).toBeVisible();await expect(page.locator('.status')).not.toContainText('running');await page.locator('.finding').first().click();await expect(page.locator('.cm-editor')).toBeVisible();}
test('navigate, draft an obligation, review, apply, and reanalyze',async({page})=>{
  await selectFinding(page);
  await page.getByRole('button',{name:'Report root',exact:true}).click();
  await expect(page.locator('.filename')).toContainText('src/lib.rs');
  await page.getByLabel('Documentation explanation').fill('Panics when this demonstration function is called.');
  await page.getByRole('button',{name:'Document obligation',exact:true}).click();
  await expect(page.locator('.diff')).toContainText('/// # Panics');
  expect(await readFile(join(dir,'src/lib.rs'),'utf8')).not.toContain('///');
  await page.screenshot({path:join(repo,'target/audit-review.png'),fullPage:true});
  await page.getByRole('button',{name:'Apply file & reanalyze'}).click();
  await expect(page.locator('.status')).toHaveText('complete');
  await expect(page.locator('.finding')).toHaveCount(0);
  expect(await readFile(join(dir,'src/lib.rs'),'utf8')).toContain('/// # Panics');
});
test('manual drafts persist and external changes prevent application',async({page})=>{
  await selectFinding(page);
  await page.locator('.cm-content').click();await page.keyboard.press('ControlOrMeta+Home');await page.keyboard.insertText('// manual audit note\n');
  await page.getByRole('button',{name:'Save draft',exact:true}).click();await expect(page.locator('.draft')).toHaveCount(1);
  await stop();await launch();await page.goto(url);await expect(page.locator('.draft')).toHaveCount(1);
  await expect(page.locator('.status')).not.toContainText('running');
  await page.locator('.draft').click();await expect(page.locator('.diff')).toContainText('manual audit note');
  await writeFile(join(dir,'src/lib.rs'),'// external edit\npub fn risky() {}\n');
  await page.getByRole('button',{name:'Apply file & reanalyze'}).click();await expect(page.getByRole('alert')).toContainText('source changed');
  expect(await readFile(join(dir,'src/lib.rs'),'utf8')).toContain('external edit');
});

for(const [effect,heading,source] of [
  ['allocation','Allocations','pub fn boxed() -> Box<u32> {\n    Box::new(7)\n}\n'],
  ['safety','Safety','pub unsafe fn read(p: *const u8) -> u8 {\n    unsafe { *p }\n}\n'],
]) {
  test(`${effect} uses the same guided obligation workflow`,async({page})=>{
    await stop();await writeFile(join(dir,'src/lib.rs'),source);await launch(effect);
    await selectFinding(page);
    await page.getByLabel('Documentation explanation').fill('The caller must uphold the documented preconditions.');
    await page.getByRole('button',{name:'Document obligation',exact:true}).click();
    await expect(page.locator('.diff')).toContainText(`/// # ${heading}`);
    const response=page.waitForResponse(r=>r.url().endsWith('/api/v1/apply'));
    await page.getByRole('button',{name:'Apply file & reanalyze'}).click();
    expect((await response).ok()).toBe(true);
    await expect.poll(()=>readFile(join(dir,'src/lib.rs'),'utf8')).toContain(`/// # ${heading}`);
    const origin=new URL(url).origin, token=new URL(url).hash.slice(1);
    await expect.poll(async()=>{const r=await fetch(origin+'/api/v1/analysis',{headers:{'x-audit-token':token}});return (await r.json()).running;}).toBe(false);
  });
}

for (const viewport of [{width:1440,height:900},{width:900,height:700},{width:1440,height:480}]) {
  test(`details stay anchored while navigating at ${viewport.width}x${viewport.height}`,async({page})=>{
    await stop();
    const calls=Array.from({length:24},(_,i)=>`fn hop${i}() { hop${i+1}(); }`).join('\n');
    await writeFile(join(dir,'src/lib.rs'),`pub fn first() { hop0(); }\npub fn second() { hop0(); }\n${calls}\n${'// source padding\n'.repeat(300)}fn hop24() {\n    panic!("origin far down the file");\n}\n`);
    await launch();await page.setViewportSize(viewport);await page.goto(url);
    const first=page.locator('.finding').filter({has:page.locator('strong',{hasText:'::first'})});
    const second=page.locator('.finding').filter({has:page.locator('strong',{hasText:'::second'})});
    await expect(first).toBeVisible();await expect(page.locator('.status')).not.toContainText('running');await first.click();
    await expect(page.locator('.cm-editor')).toBeVisible();
    const middle=page.getByLabel('Requirements and call trace');
    const input=page.getByLabel('Documentation explanation');
    await expect(page.getByLabel('Selected effect')).toBeInViewport({ratio:1});
    await expect(input).toBeInViewport({ratio:1});
    await expect(page.getByRole('button',{name:'Document obligation',exact:true})).toBeInViewport({ratio:1});
    await expect.poll(()=>page.locator('.cm-scroller').evaluate(e=>e.scrollTop)).toBeGreaterThan(1000);
    await input.fill('Keep this explanation while navigating the trace.');
    await middle.evaluate(e=>e.scrollTop=e.scrollHeight);
    const scroll=await middle.evaluate(e=>e.scrollTop);
    expect(scroll).toBeGreaterThan(0);
    await middle.locator('.trace button').last().click();
    await expect(input).toHaveValue('Keep this explanation while navigating the trace.');
    await expect.poll(()=>middle.evaluate(e=>e.scrollTop)).toBe(scroll);
    await expect(input).toBeInViewport({ratio:1});
    await second.click();
    await expect(page.locator('.finding.selected strong')).toContainText('::second');
    await expect.poll(()=>middle.evaluate(e=>e.scrollTop)).toBe(0);
    await expect(input).toBeInViewport({ratio:1});
    await expect(page.getByRole('button',{name:'Document obligation',exact:true})).toBeInViewport({ratio:1});
    expect(await page.evaluate(()=>({top:window.scrollY,height:document.documentElement.scrollHeight,viewport:innerHeight}))).toEqual({top:0,height:viewport.height,viewport:viewport.height});
    await page.screenshot({path:join(repo,`target/audit-layout-${viewport.width}x${viewport.height}.png`),fullPage:true});
  });
}
