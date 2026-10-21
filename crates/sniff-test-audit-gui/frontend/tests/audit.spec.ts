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
async function draftDocumentation(page:any,heading:string,explanation:string){
  await page.getByRole('button',{name:'Report root',exact:true}).click();
  await page.locator('.cm-content').click();
  await page.keyboard.press('ControlOrMeta+Home');
  await page.keyboard.insertText(`/// # ${heading}\n/// ${explanation}\n`);
  await page.getByRole('button',{name:'Save draft',exact:true}).click();
  await page.getByRole('button',{name:'Review diff',exact:true}).click();
}
async function expectSimpleDetails(page:any){
  const details=page.getByLabel('Effect details',{exact:true});
  await expect(details.locator('h2')).toHaveCount(0);
  await expect(details.getByRole('heading',{name:'Requirements',exact:true})).toHaveCount(0);
  await expect(page.getByLabel('Draft documentation',{exact:true})).toHaveCount(0);
  await expect(details.getByRole('heading',{name:'Navigate',exact:true})).toBeVisible();
  await expect(details.getByRole('heading',{name:'Call trace',exact:true})).toBeVisible();
}
test('navigate, draft an obligation, review, apply, and reanalyze',async({page})=>{
  await selectFinding(page);
  await page.getByRole('button',{name:'Report root',exact:true}).click();
  await expect(page.locator('.filename')).toContainText('src/lib.rs');
  await expectSimpleDetails(page);
  await draftDocumentation(page,'Panics','Panics when this demonstration function is called.');
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
  test(`${effect} uses the same source editing workflow`,async({page})=>{
    await stop();await writeFile(join(dir,'src/lib.rs'),source);await launch(effect);
    await selectFinding(page);
    await expectSimpleDetails(page);
    await draftDocumentation(page,heading,'The caller must uphold the documented preconditions.');
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
    await expectSimpleDetails(page);
    const middle=page.getByLabel('Navigation and call trace');
    await expect(page.getByLabel('Selected effect')).toBeInViewport({ratio:1});
    await expect.poll(()=>page.locator('.cm-scroller').evaluate(e=>e.scrollTop)).toBeGreaterThan(1000);
    await middle.evaluate(e=>e.scrollTop=e.scrollHeight);
    const scroll=await middle.evaluate(e=>e.scrollTop);
    expect(scroll).toBeGreaterThan(0);
    await middle.locator('.trace button').last().click();
    await expect.poll(()=>middle.evaluate(e=>e.scrollTop)).toBe(scroll);
    await second.click();
    await expect(page.locator('.finding.selected strong')).toContainText('::second');
    await expect.poll(()=>middle.evaluate(e=>e.scrollTop)).toBe(0);
    expect(await page.evaluate(()=>({top:window.scrollY,height:document.documentElement.scrollHeight,viewport:innerHeight}))).toEqual({top:0,height:viewport.height,viewport:viewport.height});
    await page.screenshot({path:join(repo,`target/audit-layout-${viewport.width}x${viewport.height}.png`),fullPage:true});
  });
}

 test('inline justification inserts a blank template at the explanation cursor',async({page})=>{
  await selectFinding(page);
  await page.getByRole('button',{name:'Justify here',exact:true}).click();
  await expect(page.locator('.cm-line').filter({hasText:'// PANIC:'})).toHaveCount(1);
  await expect(page.locator('.cm-content')).toBeFocused();
  await page.keyboard.insertText('This panic is intentional.');
  await expect(page.locator('.cm-content')).toContainText('// PANIC: This panic is intentional.');
  expect(await readFile(join(dir,'src/lib.rs'),'utf8')).not.toContain('// PANIC:');
  await page.getByRole('button',{name:'Save draft',exact:true}).click();
  await page.getByRole('button',{name:'Review diff',exact:true}).click();
  await expect(page.locator('.diff')).toContainText('// PANIC: This panic is intentional.');
 });
 test('inline obligation belongs to the origin helper and is undoable',async({page})=>{
  await stop();await writeFile(join(dir,'src/lib.rs'),'pub fn entry() { helper(); }\nfn helper() {\n    panic!("test");\n}\n');await launch();
  await selectFinding(page);
  await page.getByRole('button',{name:'Obligation location',exact:true}).click();
  await page.getByRole('button',{name:'Propagate to callers',exact:true}).click();
  await expect(page.locator('.cm-content')).toContainText('/// # Panics');
  await page.keyboard.press('ControlOrMeta+z');
  await expect(page.locator('.cm-content')).not.toContainText('/// # Panics');
  await page.reload();await selectFinding(page);
  await page.getByRole('button',{name:'Obligation location',exact:true}).click();
  await page.getByRole('button',{name:'Propagate to callers',exact:true}).click();
  await expect(page.locator('.cm-content')).toContainText('/// # Panics');
  await page.keyboard.insertText('Always panics.');
  await page.getByRole('button',{name:'Save draft',exact:true}).click();
  await page.getByRole('button',{name:'Review diff',exact:true}).click();
  await expect(page.locator('.diff')).toContainText('/// Always panics.');
  await page.getByRole('button',{name:'Apply file & reanalyze'}).click();
  await expect.poll(()=>readFile(join(dir,'src/lib.rs'),'utf8')).toContain('pub fn entry() { helper(); }\n/// # Panics\n///\n/// Always panics.\nfn helper()');
 });

for (const action of ['Justify here','Propagate to callers']) {
  test(`${action} returns after undo and deleting the inserted documentation`,async({page})=>{
    await selectFinding(page);
    const prompts=page.locator('.inline-prompt');
    await expect(prompts).toHaveCount(2);
    await expect(prompts).toContainText(["Document the caller's obligation",'Explain why this is valid']);
    await expect(prompts).not.toContainText(['Panics','PANIC']);
    await page.getByRole('button',{name:action,exact:true}).click();
    await expect(prompts).toHaveCount(0);
    await expect(page.locator('.cm-content')).toBeFocused();
    await page.keyboard.press('ControlOrMeta+z');
    await expect(prompts).toHaveCount(2);
    await expect(page.locator('.cm-content')).toBeFocused();
    await page.keyboard.press('ControlOrMeta+Shift+z');
    await expect(prompts).toHaveCount(0);
    await page.keyboard.press('ControlOrMeta+z');
    await expect(prompts).toHaveCount(2);
    await page.getByRole('button',{name:action,exact:true}).click();
    await expect(prompts).toHaveCount(0);
    await expect(page.locator('.cm-content')).toBeFocused();
    await page.keyboard.insertText('Reason');
    await page.keyboard.press('Backspace');
    await expect(prompts).toHaveCount(0);
    // Delete the whole inserted documentation, leaving the analyzed source intact.
    await page.keyboard.press('ControlOrMeta+a');
    await page.keyboard.press('ArrowLeft');
    const inserted=action==='Justify here'?'    // PANIC: Reaso\n':'/// # Panics\n///\n/// Reaso\n';
    if(action==='Justify here')for(let i=0;i<'pub fn risky() {\n'.length;i++)await page.keyboard.press('ArrowRight');
    for(let i=0;i<inserted.length;i++)await page.keyboard.press('Shift+ArrowRight');
    await page.keyboard.press('Backspace');
    await expect(prompts).toHaveCount(2);
    await expect(page.locator('.cm-content')).toBeFocused();
    await page.getByRole('button',{name:action,exact:true}).click();
    await expect(prompts).toHaveCount(0);
    await expect(page.locator('.cm-content')).toBeFocused();
    await page.keyboard.insertText('A fresh explanation.');
    await expect(page.locator('.cm-content')).toContainText('A fresh explanation.');
    expect(await readFile(join(dir,'src/lib.rs'),'utf8')).not.toContain('A fresh explanation.');
  });
}

test('multiline selection stays visible on the active line and deletes only selected text',async({page})=>{
  await stop();
  const source=`pub fn risky() {\n    panic!("${'a long explanation '.repeat(10)}");\n}\n`;
  await writeFile(join(dir,'src/lib.rs'),source);await launch();
  await selectFinding(page);
  const content=page.locator('.cm-content');
  for(const width of [1440,900])for(const reverse of [false,true]) {
    await page.setViewportSize({width,height:900});
    await content.click();
    await page.keyboard.press('ControlOrMeta+a');
    await page.keyboard.press('ArrowLeft');
    const start=4,end=source.length-3;
    for(let i=0;i<(reverse?end:start);i++)await page.keyboard.press('ArrowRight');
    for(let i=start;i<end;i++)await page.keyboard.press(reverse?'Shift+ArrowLeft':'Shift+ArrowRight');
    const active=page.locator('.cm-activeLine');
    const color=await active.evaluate(e=>getComputedStyle(e).backgroundColor);
    expect(color).toMatch(/^rgba\(/);
    expect(Number(color.split(',').at(-1)!.replace(')',''))).toBeLessThan(0.25);
    await expect(page.locator('.cm-selectionBackground').first()).toBeVisible();
    await page.screenshot({path:join(repo,`target/audit-selection-${width}-${reverse?'backward':'forward'}.png`)});
    await page.keyboard.press('Backspace');
    await expect.poll(()=>content.locator('.cm-line').allTextContents()).toEqual((source.slice(0,start)+source.slice(end)).split('\n'));
    await page.keyboard.press('ControlOrMeta+z');
    await expect.poll(()=>content.locator('.cm-line').allTextContents()).toEqual(source.split('\n'));
  }
});
