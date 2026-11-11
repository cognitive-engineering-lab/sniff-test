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
async function stop(){if(server?.exitCode===null && server?.signalCode===null){await new Promise<void>(resolve=>{server.once('exit',()=>resolve());if(process.platform==='win32')server.kill('SIGTERM');else process.kill(-server.pid!,'SIGTERM');});}}
test.beforeEach(async()=>{
  dir=await mkdtemp(join(tmpdir(),'sniff-audit-browser-'));await mkdir(join(dir,'src'));
  await writeFile(join(dir,'Cargo.toml'),'[package]\nname="audit-browser-fixture"\nversion="0.1.0"\nedition="2024"\n[workspace]\n');
  await copyFile(join(repo,'rust-toolchain.toml'),join(dir,'rust-toolchain.toml'));
  await writeFile(join(dir,'src/lib.rs'),'pub fn risky() {\n    panic!("intentional test panic");\n}\n');
  await launch();
});
test.afterEach(async()=>{await stop();if(dir)await rm(dir,{recursive:true,force:true,maxRetries:5,retryDelay:100});});
async function selectFinding(page:any){await page.goto(url);await page.locator('.group').first().click();await expect(page.locator('.finding').first()).toBeVisible();await expect(page.locator('.status')).not.toContainText('running');await page.locator('.finding').first().click();await expect(page.locator('.cm-editor')).toBeVisible();}

for(const [kind,dependency,display] of [
  ['registry','/home/example/.cargo/registry/src/index.crates.io-123/wyz-0.5.1/src/lib.rs','wyz-0.5.1/src/lib.rs'],
  ['toolchain','/home/example/.rustup/toolchains/nightly-2026-05-01-aarch64-apple-darwin/lib/rustlib/src/rust/library/core/src/option.rs','nightly-2026-05-01-aarch64-apple-darwin/lib/rustlib/src/rust/library/core/src/option.rs'],
])test(`${kind} paths are shortened consistently while navigation retains the full path`,async({page})=>{
  const original=join(dir,'src/lib.rs');
  await page.route('**/api/v1/findings?*',async route=>{
    const response=await route.fetch(),result=await response.json();
    for(const group of result.groups){
      if(group.label){
        group.label=group.label.replace(group.path,dependency);
        group.path=dependency;
      }else group.key=dependency;
    }
    await route.fulfill({response,json:result});
  });
  await page.route('**/api/v1/finding?*',async route=>{
    const response=await route.fetch(),finding=await response.json();
    finding.audit.source.path=dependency;
    for(const step of finding.audit.trace)if(step.location)step.location.path=dependency;
    finding.navigation.source.path=dependency;
    for(const location of finding.navigation.trace)if(location)location.path=dependency;
    await route.fulfill({response,json:finding});
  });
  let requestedPath:string|null=null;
  await page.route('**/api/v1/buffer?*',async route=>{
    const request=new URL(route.request().url());
    if(request.searchParams.get('path')!==dependency){await route.continue();return;}
    requestedPath=request.searchParams.get('path');
    request.searchParams.set('path',original);
    const response=await route.fetch({url:request.href}),buffer=await response.json();
    await route.fulfill({response,json:{...buffer,path:dependency,writable:false}});
  });
  await selectFinding(page);
  await expect(page.locator('.group-path')).toHaveText(display);
  await expect(page.locator('.group')).toHaveAttribute('title',dependency);
  await expect(page.locator('.filename')).toHaveText(display);
  await expect(page.locator('.filename')).toHaveAttribute('title',dependency);
  await expect(page.locator('.trace small').first()).toContainText(`${display}:`);
  await expect(page.locator('.trace small').first()).toHaveAttribute('title',dependency);
  expect(requestedPath).toBe(dependency);
  await page.getByRole('button',{name:'Report root',exact:true}).click();
  await expect(page.locator('.filename')).toHaveText('src/lib.rs');
  requestedPath=null;
  await page.locator('.trace button').first().click();
  await expect(page.locator('.filename')).toHaveText(display);
  expect(requestedPath).toBe(dependency);
  await page.getByRole('button',{name:'Invert effect'}).click();
  await expect(page.locator('.group-path')).toContainText(`${display}:`);
  await expect(page.locator('.group-path')).not.toContainText('/home/example');
  await expect(page.locator('.group')).toHaveAttribute('title',new RegExp(dependency.replaceAll('.','\\.')));
});

async function editDocumentation(page:any,heading:string,explanation:string){
  await page.getByRole('button',{name:'Report root',exact:true}).click();
  await page.locator('.cm-content').click();
  await page.keyboard.press('ControlOrMeta+Home');
  await page.keyboard.insertText(`/// # ${heading}\n/// ${explanation}\n`);
}
async function expectSimpleDetails(page:any){
  const details=page.getByLabel('Effect details',{exact:true});
  await expect(details.locator('h2')).toHaveCount(0);
  await expect(details.getByRole('heading',{name:'Requirements',exact:true})).toHaveCount(0);
  await expect(page.getByLabel('Draft documentation',{exact:true})).toHaveCount(0);
  await expect(details.getByRole('heading',{name:'Navigate',exact:true})).toBeVisible();
  await expect(details.locator('.details-scroll > button.link')).toHaveCount(3);
  for(const name of ['Report root','Effect source','Contract'])
    await expect(details.getByRole('button',{name:new RegExp('^'+name)})).toBeVisible();
  await expect(details.getByRole('heading',{name:'Call trace',exact:true})).toBeVisible();
}
test('finding jumps follow saved edits and retain approximate deleted sites',async({page})=>{
  await selectFinding(page);
  const finding=page.locator('.finding').first();
  const selection=()=>page.evaluate(()=>window.getSelection()?.toString());
  await page.locator('.cm-content').focus();await page.keyboard.press('ControlOrMeta+Home');
  await page.keyboard.insertText('// λ 🦀 before the effect\n');
  // Clicking a finding must await the pending save before choosing its destination.
  await expect(page.getByLabel('Source save status')).toHaveText('Unsaved changes');
  await finding.click();
  await expect.poll(selection).toContain('panic!');
  await expect(page.locator('.error')).toHaveCount(0);
  await page.getByRole('button',{name:'Report root',exact:true}).click();
  await expect.poll(selection).toContain('pub fn risky');
  await page.getByRole('button',{name:'Effect source',exact:true}).click();
  await expect.poll(selection).toContain('panic!');
  await page.locator('.trace button').first().click();
  await expect.poll(selection).toContain('panic!');
  await expect(page.locator('.error')).toHaveCount(0);
  await page.locator('.cm-content').focus();await page.keyboard.press('ControlOrMeta+z');
  await finding.click();
  await expect.poll(selection).toContain('panic!');
  await page.locator('.cm-content').focus();await page.keyboard.press('ControlOrMeta+Shift+z');
  await finding.click();
  await expect.poll(selection).toContain('panic!');
  await expect(page.locator('.error')).toHaveCount(0);
  await page.locator('.cm-content').focus();await page.keyboard.press('ControlOrMeta+a');
  await page.keyboard.insertText('pub fn risky() {\n    something_else();\n}\n');
  await finding.click();
  await expect(page.getByText('Approximate location; reanalyze to refresh.',{exact:true})).toBeVisible();
  await expect(page.locator('.error')).toHaveCount(0);
  await page.locator('.cm-content').focus();await page.keyboard.press('ControlOrMeta+a');await page.keyboard.press('Backspace');
  await finding.click();
  await expect(page.getByText('Approximate location; reanalyze to refresh.',{exact:true})).toBeVisible();
  await expect.poll(selection).toBe('');
  await expect(page.locator('.error')).toHaveCount(0);
  await page.getByRole('button',{name:'↻ Reanalyze',exact:true}).click();
  await expect(page.locator('.status')).toHaveText('complete');
  await expect(page.locator('.finding')).toHaveCount(0);
});

test('Back history follows Unicode CRLF edits in the same file',async({page})=>{
  await stop();
  await writeFile(join(dir,'src/lib.rs'),'pub fn first() {\r\n    panic!("first");\r\n}\r\npub fn second() {\r\n    panic!("second");\r\n}\r\n');
  await launch();await selectFinding(page);
  await page.locator('.finding').last().click();
  await expect.poll(()=>page.evaluate(()=>window.getSelection()?.toString())).toContain('panic!("second")');
  await page.locator('.finding').first().click();
  await expect.poll(()=>page.evaluate(()=>window.getSelection()?.toString())).toContain('panic!("first")');
  await page.locator('.cm-content').focus();await page.keyboard.press('ControlOrMeta+Home');
  await page.keyboard.insertText('// λ 🦀 before both sites\n');
  await page.getByRole('button',{name:'← Back',exact:true}).click();
  await expect.poll(()=>page.evaluate(()=>window.getSelection()?.toString())).toContain('panic!("second")');
  await page.getByRole('button',{name:'← Back',exact:true}).click();
  await expect.poll(()=>page.evaluate(()=>window.getSelection()?.toString())).toContain('panic!("first")');
  await expect(page.locator('.error')).toHaveCount(0);
});

test('left panel tracks partial mixed and filtered audit progress',async({page})=>{
  await stop();
  await writeFile(join(dir,'src/lib.rs'),'pub fn first() {\n    panic!("first");\n}\npub fn second() {\n    panic!("second");\n}\n');
  await launch();await selectFinding(page);
  await expect(page.locator('.finding')).toHaveCount(2);
  await page.getByRole('button',{name:'Justify here',exact:true}).click();
  await expect(page.locator('.cm-content')).toContainText('// PANIC:');
  await page.keyboard.press('ControlOrMeta+s');
  await expect(page.getByLabel('Source save status')).toHaveText('Saved');
  await expect(page.locator('.finding-list .audit-progress')).toHaveCount(0);
  await page.route('**/api/v1/source/save',route=>route.abort(),{times:1});
  await page.keyboard.insertText('The invariant holds.');
  await page.keyboard.press('ControlOrMeta+s');
  await expect(page.getByLabel('Source save status')).toHaveText('Save failed');
  await expect(page.locator('.finding-list .audit-progress')).toHaveCount(0);
  await page.getByRole('button',{name:'Retry',exact:true}).click();
  await expect(page.getByLabel('Source save status')).toHaveText('Saved');
  await expect(page.locator('.group .audit-progress')).toHaveText('1/2');
  await expect(page.locator('.finding').first().getByLabel('Justification saved',{exact:true})).toBeVisible();
  await page.locator('.group').click();
  await expect(page.locator('.group .audit-progress')).toHaveText('1/2');
  await page.locator('.group').click();
  await page.locator('.finding').last().click();
  await page.getByRole('button',{name:'Propagate to callers',exact:true}).click();
  await expect(page.locator('.cm-content')).toContainText('/// # Panics');
  await page.keyboard.insertText('The caller handles this panic.');
  await page.keyboard.press('ControlOrMeta+s');
  await expect(page.getByLabel('Source save status')).toHaveText('Saved');
  for(const mark of ['Justification saved','Propagation saved'])await expect(page.locator('.group').getByLabel(mark,{exact:true})).toBeVisible();
  await expect(page.locator('.finding').last().getByLabel('Propagation saved',{exact:true})).toBeVisible();
  await page.getByLabel('Search findings',{exact:true}).fill('first');
  await expect(page.locator('.finding')).toHaveCount(1);
  await expect(page.locator('.group').getByLabel('Justification saved',{exact:true})).toBeVisible();
  await expect(page.locator('.group').getByLabel('Propagation saved',{exact:true})).toHaveCount(0);
  await page.getByLabel('Search findings',{exact:true}).fill('');
  await page.getByRole('button',{name:'⇄ Invert effect',exact:true}).click();
  await expect(page.locator('.group')).toHaveCount(2);
  for(const mark of ['Justification saved','Propagation saved'])await expect(page.locator('.group').getByLabel(mark,{exact:true})).toBeVisible();
  await page.screenshot({path:join(repo,'target/audit-left-progress.png'),fullPage:true});
  await page.getByRole('button',{name:'↻ Reanalyze',exact:true}).click();
  await expect(page.locator('.status')).toHaveText('complete');
  await expect(page.locator('.group')).toHaveCount(0);
});

test('source documentation autosaves and manual analysis waits for writes and pauses editing',async({page})=>{
  await selectFinding(page);await expectSimpleDetails(page);
  await expect(page.getByText('SAVED DRAFTS',{exact:false})).toHaveCount(0);
  await editDocumentation(page,'Panics','Panics when this demonstration function is called.');
  let release!:()=>void;
  const held=new Promise<void>(resolve=>release=resolve);
  await page.route('**/api/v1/analysis',async route=>{if(route.request().method()==='POST')await held;await route.continue();});
  await page.getByRole('button',{name:'↻ Reanalyze',exact:true}).click();
  await expect(page.locator('.cm-content')).toHaveAttribute('aria-readonly','true');
  await expect.poll(()=>readFile(join(dir,'src/lib.rs'),'utf8')).toContain('/// # Panics');
  release();
  await expect(page.locator('.status')).toHaveText('complete');
  await expect(page.locator('.cm-content')).not.toHaveAttribute('aria-readonly','true');
  await expect(page.locator('.finding')).toHaveCount(0);
});

test('autosave resets its idle timer and preserves editor identity and undo',async({page})=>{
  await selectFinding(page);
  const original=await readFile(join(dir,'src/lib.rs'),'utf8');
  await page.evaluate(()=>(window as any).originalEditor=document.querySelector('.cm-content'));
  await page.locator('.cm-content').focus();await page.keyboard.press('ControlOrMeta+Home');
  await page.keyboard.insertText('// first edit\n');
  await expect(page.getByLabel('Source save status')).toHaveText('Unsaved changes');
  await page.waitForTimeout(450);expect(await readFile(join(dir,'src/lib.rs'),'utf8')).toBe(original);
  await page.keyboard.insertText('// second edit\n');
  await page.waitForTimeout(650);expect(await readFile(join(dir,'src/lib.rs'),'utf8')).toBe(original);
  await expect(page.getByLabel('Source save status')).toHaveText('Saved');
  expect(await readFile(join(dir,'src/lib.rs'),'utf8')).toContain('// first edit\n// second edit');
  expect(await page.evaluate(()=>(window as any).originalEditor===document.querySelector('.cm-content'))).toBe(true);
  await expect(page.locator('.cm-content')).toBeFocused();
  await page.screenshot({path:join(repo,'target/audit-autosave.png'),fullPage:true});
  await page.keyboard.press('ControlOrMeta+z');
  await page.keyboard.press('ControlOrMeta+s');
  await expect(page.getByLabel('Source save status')).toHaveText('Saved');
  expect(await readFile(join(dir,'src/lib.rs'),'utf8')).not.toContain('// second edit');
  await page.keyboard.press('ControlOrMeta+Shift+z');await page.keyboard.press('ControlOrMeta+s');
  await expect.poll(()=>readFile(join(dir,'src/lib.rs'),'utf8')).toContain('// second edit');
});

test('autosave retains local text on external conflicts and reloads explicitly',async({page})=>{
  await selectFinding(page);
  const original=await readFile(join(dir,'src/lib.rs'),'utf8');
  await page.locator('.cm-content').focus();await page.keyboard.press('ControlOrMeta+Home');await page.keyboard.insertText('// local edit\n');
  await writeFile(join(dir,'src/lib.rs'),'// external edit\n'+original);
  await expect(page.getByLabel('Source save status')).toHaveText('Save failed');
  await expect(page.getByRole('alert')).toContainText('Source changed outside audit');
  await expect(page.locator('.cm-content')).toContainText('// local edit');
  expect(await readFile(join(dir,'src/lib.rs'),'utf8')).not.toContain('// local edit');
  await expect(page.getByRole('button',{name:'Copy edits',exact:true})).toBeVisible();
  await page.getByRole('button',{name:'Reload file',exact:true}).click();
  await expect(page.locator('.cm-content')).toContainText('// external edit');
  await expect(page.locator('.cm-content')).not.toContainText('// local edit');
  await expect(page.getByLabel('Source save status')).toHaveText('Saved');
});

test('autosave serializes delayed acknowledgments without replacing newer typing',async({page})=>{
  await selectFinding(page);
  let release!:()=>void,seen!:()=>void;
  const held=new Promise<void>(resolve=>release=resolve),requested=new Promise<void>(resolve=>seen=resolve);
  const revisions:number[]=[];
  await page.route('**/api/v1/source/save',async route=>{
    revisions.push(route.request().postDataJSON().revision);
    if(revisions.length===1){seen();await held;}
    await route.continue();
  });
  await page.locator('.cm-content').focus();await page.keyboard.press('ControlOrMeta+Home');await page.keyboard.insertText('// first\n');
  await page.keyboard.press('ControlOrMeta+s');await requested;
  await page.keyboard.insertText('// newer\n');release();
  await expect(page.getByLabel('Source save status')).toHaveText('Saved');
  await expect(page.locator('.cm-content')).toContainText('// newer');
  expect(await readFile(join(dir,'src/lib.rs'),'utf8')).toContain('// first\n// newer');
  expect(revisions).toEqual([0,1]);
});

test('reanalyzed external source changes refresh the same open editor before autosaving',async({page})=>{
  await selectFinding(page);
  const original=await readFile(join(dir,'src/lib.rs'),'utf8');
  await writeFile(join(dir,'src/lib.rs'),'// externally updated\n'+original);
  const analysis=page.waitForResponse(response=>response.url().endsWith('/api/v1/analysis')&&response.request().method()==='POST');
  await page.getByRole('button',{name:'↻ Reanalyze',exact:true}).click();await analysis;
  await expect(page.locator('.status')).toHaveText('complete');
  await page.locator('.finding').first().click();
  await expect(page.locator('.cm-content')).toContainText('// externally updated');
  await expect(page.getByRole('button',{name:'Justify here',exact:true})).toBeVisible();
  await expect(page.locator('.status')).toHaveText('complete');
  await page.locator('.cm-content').focus();await page.keyboard.press('ControlOrMeta+Home');
  await page.keyboard.insertText('// own edit\n');await page.keyboard.press('ControlOrMeta+s');
  await expect(page.getByLabel('Source save status')).toHaveText('Saved');
  expect(await readFile(join(dir,'src/lib.rs'),'utf8')).toContain('// own edit\n// externally updated');
});

for(const waitForSave of [false,true])for(const action of ['Justify here','Propagate to callers']) {
 test(`${action} hides prompts ${waitForSave?'after':'before'} autosave while analysis is stale`,async({page})=>{
  await selectFinding(page);
  await page.locator('.cm-content').focus();await page.keyboard.press('ControlOrMeta+Home');
  await page.keyboard.insertText('// λ before the verified sites\n');
  for(const label of ['Justify here','Propagate to callers'])await expect(page.getByRole('button',{name:label,exact:true})).toBeVisible();
  if(waitForSave)await expect(page.getByLabel('Source save status')).toHaveText('Saved');
  await page.getByRole('button',{name:action,exact:true}).click();
  await expect(page.locator('.cm-content')).toContainText(action==='Justify here'?'// PANIC:':'/// # Panics');
  await expect(page.locator('.inline-prompt')).toHaveCount(0);
  await page.keyboard.insertText('This panic is intentional.');
  await page.keyboard.press('ControlOrMeta+s');
  await expect(page.getByLabel('Source save status')).toHaveText('Saved');
  await expect(page.locator('.inline-prompt')).toHaveCount(0);
  const mark=action==='Justify here'?'Justification saved':'Propagation saved';
  await expect(page.locator('.finding.selected').getByLabel(mark,{exact:true})).toBeVisible();
  await expect(page.locator('.group').getByLabel(mark,{exact:true})).toBeVisible();
  const source=await readFile(join(dir,'src/lib.rs'),'utf8');
  expect(source).toContain('This panic is intentional.');
  expect(source).toContain('// λ before the verified sites');
  await expect(page.locator('.status')).toContainText('stale');
  await page.reload();
  await page.locator('.group').first().click();
  await page.locator('.finding').first().click();
  await expect(page.locator('.cm-editor')).toBeVisible();
  await expect(page.locator('.inline-prompt')).toHaveCount(0);
 });
}

test('autosave retries transient failures and persists source across server restarts',async({page})=>{
  await selectFinding(page);
  await page.route('**/api/v1/source/save',route=>route.abort(),{times:1});
  await page.locator('.cm-content').focus();await page.keyboard.press('ControlOrMeta+Home');await page.keyboard.insertText('// saved audit note\n');
  await page.keyboard.press('ControlOrMeta+s');
  await expect(page.getByLabel('Source save status')).toHaveText('Save failed');
  await page.getByRole('button',{name:'Retry',exact:true}).click();
  await expect(page.getByLabel('Source save status')).toHaveText('Saved');
  await stop();await launch();await selectFinding(page);
  await expect(page.locator('.cm-content')).toContainText('// saved audit note');
  await expect(page.getByText('SAVED DRAFTS',{exact:false})).toHaveCount(0);
});

for(const [effect,heading,source] of [
  ['allocation','Allocations','pub fn boxed() -> Box<u32> {\n    Box::new(7)\n}\n'],
  ['safety','Safety','pub unsafe fn read(p: *const u8) -> u8 {\n    unsafe { *p }\n}\n'],
]) {
  test(`${effect} uses the same source editing workflow`,async({page})=>{
    await stop();await writeFile(join(dir,'src/lib.rs'),source);await launch(effect);
    await selectFinding(page);
    await expectSimpleDetails(page);
    await editDocumentation(page,heading,'The caller must uphold the documented preconditions.');
    await expect(page.locator('.inline-prompt')).toHaveCount(0);
    await page.getByRole('button',{name:'↻ Reanalyze',exact:true}).click();
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
    await page.locator('.group').first().click();
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
  await expect.poll(()=>readFile(join(dir,'src/lib.rs'),'utf8')).toContain('// PANIC: This panic is intentional.');
 });
 test('inline obligation belongs to the origin helper and is undoable',async({page})=>{
  await stop();await writeFile(join(dir,'src/lib.rs'),'pub fn entry() { helper(); }\nfn helper() {\n    panic!("test");\n}\n');await launch();
  await selectFinding(page);
  await page.getByRole('button',{name:'Effect source',exact:true}).click();
  await page.getByRole('button',{name:'Propagate to callers',exact:true}).click();
  await expect(page.locator('.cm-content')).toContainText('/// # Panics');
  await page.keyboard.press('ControlOrMeta+z');
  await expect(page.locator('.cm-content')).not.toContainText('/// # Panics');
  await page.reload();await selectFinding(page);
  await page.getByRole('button',{name:'Effect source',exact:true}).click();
  await page.getByRole('button',{name:'Propagate to callers',exact:true}).click();
  await expect(page.locator('.cm-content')).toContainText('/// # Panics');
  await page.keyboard.insertText('Always panics.');
  await page.keyboard.press('ControlOrMeta+s');
  await expect.poll(()=>readFile(join(dir,'src/lib.rs'),'utf8')).toContain('pub fn entry() { helper(); }\n/// # Panics\n///\n/// Always panics.\nfn helper()');
 });

for (const action of ['Justify here','Propagate to callers']) {
  test(`${action} hides both prompts and restores them on undo and deletion`,async({page})=>{
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
    await page.keyboard.press('ControlOrMeta+s');
    await expect(page.getByLabel('Source save status')).toHaveText('Saved');
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

for(const action of ['Justify here','Propagate to callers']) {
 test(`${action} removes empty comment lines and restores prompts immediately`,async({page})=>{
  await selectFinding(page);
  await page.getByRole('button',{name:action,exact:true}).click();
  await expect(page.locator('.inline-prompt')).toHaveCount(0);
  await page.keyboard.insertText('Explanation.');
  let release!:()=>void,seen!:()=>void;
  const held=new Promise<void>(resolve=>release=resolve),requested=new Promise<void>(resolve=>seen=resolve);
  await page.route('**/api/v1/source/save',async route=>{
    const response=await route.fetch();seen();await held;await route.fulfill({response});
  },{times:1});
  await page.keyboard.press('ControlOrMeta+s');await requested;
  await page.keyboard.press('ControlOrMeta+Home');
  if(action==='Justify here')for(let i=0;i<'pub fn risky() {\n'.length;i++)await page.keyboard.press('ArrowRight');
  const inserted=action==='Justify here'?'    // PANIC: Explanation.':'/// # Panics\n///\n/// Explanation.';
  for(let i=0;i<inserted.length;i++)await page.keyboard.press('Shift+ArrowRight');
  // Clearing the comment also removes leftover whitespace and newlines.
  await page.keyboard.insertText('\n    ');
  await expect(page.locator('.inline-prompt')).toHaveCount(2);
  await expect(page.locator('.cm-content')).toBeFocused();
  release();
  await page.keyboard.press('ControlOrMeta+s');
  await expect(page.getByLabel('Source save status')).toHaveText('Saved');
  await expect.poll(()=>readFile(join(dir,'src/lib.rs'),'utf8')).toBe('pub fn risky() {\n    panic!("intentional test panic");\n}\n');
  await expect(page.locator('.inline-prompt')).toHaveCount(2);
  await page.keyboard.press('ControlOrMeta+z');
  await expect(page.locator('.inline-prompt')).toHaveCount(0);
  await page.keyboard.press('ControlOrMeta+Shift+z');
  await expect(page.locator('.inline-prompt')).toHaveCount(2);
 });

 test(`${action} continues comments and keeps prompts hidden while editing blank lines`,async({page})=>{
  await selectFinding(page);
  await page.getByRole('button',{name:action,exact:true}).click();
  await expect(page.locator('.inline-prompt')).toHaveCount(0);
  const prefix=action==='Justify here'?'    // ':'/// ';
  await page.keyboard.insertText('First explanation.');
  await page.keyboard.press('Enter');
  await page.keyboard.insertText('Second explanation.');
  await expect(page.locator('.cm-content')).toContainText(prefix+'Second explanation.');
  await expect(page.locator('.inline-prompt')).toHaveCount(0);
  // Clear the new line, including its prefix, but keep its newline.
  await page.keyboard.press('Home');
  await page.keyboard.press('Shift+End');
  await page.keyboard.press('Backspace');
  await expect(page.locator('.inline-prompt')).toHaveCount(0);
  await page.keyboard.press('ControlOrMeta+s');
  await expect(page.getByLabel('Source save status')).toHaveText('Saved');
  await expect(page.locator('.inline-prompt')).toHaveCount(0);
  // Blur flushes saves, but does not end the comment editing session.
  await page.getByLabel('Search findings',{exact:true}).focus();
  await expect(page.locator('.inline-prompt')).toHaveCount(0);
  await page.locator('.cm-content').focus();
  await page.keyboard.press('ControlOrMeta+End');
  await expect(page.locator('.inline-prompt')).toHaveCount(2);
  await page.keyboard.press('ControlOrMeta+z');
  await expect(page.locator('.inline-prompt')).toHaveCount(0);
 });

 test(`${action} always continues empty comments through delayed saves`,async({page})=>{
  await selectFinding(page);
  await page.getByRole('button',{name:action,exact:true}).click();
  await expect(page.locator('.inline-prompt')).toHaveCount(0);
  let release!:()=>void,seen!:()=>void;
  const held=new Promise<void>(resolve=>release=resolve),requested=new Promise<void>(resolve=>seen=resolve);
  await page.route('**/api/v1/source/save',async route=>{
    const response=await route.fetch();seen();await held;await route.fulfill({response});
  },{times:1});
  await page.keyboard.insertText('Explanation.');
  await page.keyboard.press('ControlOrMeta+s');await requested;
  await page.keyboard.press('Enter');
  await page.keyboard.press('Enter');
  await page.keyboard.insertText('Still commenting.');
  const prefix=action==='Justify here'?'    // ':'/// ';
  await expect(page.locator('.cm-content')).toContainText(prefix+'Still commenting.');
  await expect(page.locator('.inline-prompt')).toHaveCount(0);
  release();
  await page.keyboard.press('ControlOrMeta+s');
  await expect(page.getByLabel('Source save status')).toHaveText('Saved');
  await expect.poll(()=>readFile(join(dir,'src/lib.rs'),'utf8')).toContain(`Explanation.\n${prefix}\n${prefix}Still commenting.`);
  await expect(page.locator('.inline-prompt')).toHaveCount(0);
  await page.keyboard.press('ControlOrMeta+End');
  await expect(page.locator('.inline-prompt')).toHaveCount(0);
 });
}

for(const [name,note,atCall,hidden] of [
  ['attached marker','    // PANIC: ',true,true],
  ['bare attached marker','    // PANIC',true,true],
  ['other effect marker','    // SAFETY: unrelated',true,false],
  ['marker with a longer name','    // PANICKING: unrelated',true,false],
  ['detached marker','    // PANIC: unrelated\n',true,false],
  ['marker inside a raw string','const NOTE: &str = r#"\n// PANIC: unrelated\n"#;',false,false],
  ['attached heading','/// # Panics\n///',false,true],
] as const) {
 test(`manual ${name} updates source prompt visibility`,async({page})=>{
  await selectFinding(page);
  await page.locator('.cm-content').focus();await page.keyboard.press('ControlOrMeta+Home');
  if(atCall)await page.keyboard.press('ArrowDown');
  await page.keyboard.press('Home');
  await page.keyboard.insertText(note+'\n');
  await expect(page.locator('.inline-prompt')).toHaveCount(hidden?0:2);
  await page.keyboard.press('ControlOrMeta+s');
  await expect(page.getByLabel('Source save status')).toHaveText('Saved');
  await expect(page.locator('.inline-prompt')).toHaveCount(hidden?0:2);
  await page.keyboard.press('ControlOrMeta+z');
  await expect(page.locator('.inline-prompt')).toHaveCount(2);
 });
}

for(const action of ['Justify here','Propagate to callers'])for(const remove of [false,true]) {
 test(`${action} preserves ${remove?'restored':'hidden'} prompts through delayed save acknowledgments`,async({page})=>{
  await selectFinding(page);
  await page.getByRole('button',{name:action,exact:true}).click();
  await expect(page.locator('.inline-prompt')).toHaveCount(0);
  let release!:()=>void,seen!:()=>void;
  const held=new Promise<void>(resolve=>release=resolve),requested=new Promise<void>(resolve=>seen=resolve);
  await page.route('**/api/v1/source/save',async route=>{
    const response=await route.fetch();seen();await held;await route.fulfill({response});
  },{times:1});
  await page.keyboard.insertText('First explanation.');
  await page.keyboard.press('ControlOrMeta+s');await requested;
  if(remove){
    await page.keyboard.press('ControlOrMeta+Home');
    if(action==='Justify here')await page.keyboard.press('ArrowDown');
    await page.keyboard.press('Home');
    const inserted=action==='Justify here'?'    // PANIC: First explanation.\n':'/// # Panics\n///\n/// First explanation.\n';
    for(let i=0;i<inserted.length;i++)await page.keyboard.press('Shift+ArrowRight');
    await page.keyboard.press('Backspace');
  }else await page.keyboard.insertText(' A newer explanation.');
  await expect(page.locator('.inline-prompt')).toHaveCount(remove?2:0);
  release();
  await expect(page.getByLabel('Source save status')).toHaveText('Saved');
  await expect(page.locator('.inline-prompt')).toHaveCount(remove?2:0);
  const source=await readFile(join(dir,'src/lib.rs'),'utf8');
  if(remove)expect(source).toBe('pub fn risky() {\n    panic!("intentional test panic");\n}\n');
  else expect(source).toContain('First explanation. A newer explanation.');
 });
}

for(const action of ['Justify here','Propagate to callers']) {
 test(`${action} tracks CRLF, Unicode and multiline attributes`,async({page})=>{
  await stop();
  await writeFile(join(dir,'src/lib.rs'),'// λ\r\n#[allow(\r\n    clippy::all\r\n)]\r\npub fn risky() {\r\n    panic!("test");\r\n}\r\n');await launch();
  await selectFinding(page);
  await expect(page.locator('.inline-prompt')).toHaveCount(2);
  await page.getByRole('button',{name:action,exact:true}).click();
  await expect(page.locator('.inline-prompt')).toHaveCount(0);
  await page.keyboard.press('ControlOrMeta+s');
  await expect(page.getByLabel('Source save status')).toHaveText('Saved');
  await expect(page.locator('.inline-prompt')).toHaveCount(0);
  await page.keyboard.press('ControlOrMeta+z');
  await expect(page.locator('.inline-prompt')).toHaveCount(2);
  const source=await readFile(join(dir,'src/lib.rs'),'utf8');
  expect(source.replaceAll('\r\n','')).not.toContain('\n');
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

async function identifierBounds(page:any,line:string,identifier:string){
    return await page.locator('.cm-line').filter({hasText:line}).evaluate((element:any,identifier:string)=>{
      const walker=document.createTreeWalker(element,NodeFilter.SHOW_TEXT);let node;
      while((node=walker.nextNode())){const at=node.textContent!.indexOf(identifier);if(at>=0){const range=document.createRange();range.setStart(node,at+1);range.setEnd(node,at+2);const rect=range.getBoundingClientRect();return {x:rect.x+rect.width/2,y:rect.y+rect.height/2};}}
      throw Error('identifier missing');
    },identifier);
}
async function clickIdentifier(page:any,line:string,identifier:string,modifier=false){
    const bounds=await identifierBounds(page,line,identifier);
    const key=process.platform==='darwin'?'Meta':'Control';
    if(modifier)await page.keyboard.down(key);
    await page.mouse.click(bounds.x,bounds.y);
    if(modifier)await page.keyboard.up(key);
}

for(const stale of [false,true])test(`${stale?'stale ':''}call trace highlights the editor location across files and navigation`,async({page})=>{
  await stop();
  await writeFile(join(dir,'src/lib.rs'),'\ufeff// λ before the call\r\npub fn entry() {\r\n    helper::danger();\r\n}\r\nmod helper;\r\n');
  await writeFile(join(dir,'src/helper.rs'),'pub fn danger() {\n    panic!("trace location");\n}\n');
  await writeFile(join(dir,'src/note.rs'),'// unrelated source\n');
  await launch();await selectFinding(page);
  if(stale){
    // Saving another source file makes analysis stale without moving these calls.
    const origin=new URL(url).origin,headers={'x-audit-token':new URL(url).hash.slice(1)};
    const response=await page.request.get(origin+'/api/v1/buffer',{headers,params:{path:join(dir,'src/note.rs')}});
    expect(response.ok()).toBe(true);
    const buffer=await response.json();
    const saved=await page.request.post(origin+'/api/v1/source/save',{headers,data:{path:buffer.path,revision:buffer.revision,content:'// updated unrelated source\n'}});
    expect(saved.ok()).toBe(true);
    await expect(page.locator('.status')).toContainText('stale');
  }
  const rows=page.locator('.trace button');
  await expect.poll(()=>rows.count()).toBeGreaterThanOrEqual(2);
  const entry=rows.filter({hasText:'entry'}).first();
  const origin=rows.filter({has:page.locator('small[title$="/src/helper.rs"]')}).first();
  await entry.click();
  await expect(page.locator('.filename')).toContainText('src/lib.rs');
  await expect(entry).toHaveAttribute('aria-current','location');
  await expect(page.locator('.trace button[aria-current="location"]')).toHaveCount(1);
  const forward=await rows.allTextContents();
  const numbers=Array.from({length:forward.length},(_,i)=>i+1);
  const entries=page.locator('.trace li');
  await expect.poll(()=>entries.evaluateAll(elements=>elements.map(element=>(element as HTMLLIElement).value))).toEqual(numbers);
  const originNumber=await origin.evaluate(element=>(element.parentElement as HTMLLIElement).value);
  const originRow=page.locator(`.trace li[value="${originNumber}"] button`);
  const toggle=page.getByRole('button',{name:'Invert effect'});
  const middle=page.getByLabel('Navigation and call trace');
  await middle.evaluate(element=>element.scrollTop=element.scrollHeight);
  await toggle.click();
  await expect(page.locator('.trace')).toHaveAttribute('reversed','');
  await expect(rows).toHaveText([...forward].reverse());
  await expect.poll(()=>entries.evaluateAll(elements=>elements.map(element=>(element as HTMLLIElement).value))).toEqual([...numbers].reverse());
  await expect.poll(()=>middle.evaluate(element=>element.scrollTop)).toBe(0);
  await expect(entry).toHaveAttribute('aria-current','location');
  await expect(page.locator('.filename')).toContainText('src/lib.rs');
  await originRow.click();
  await expect(page.locator('.filename')).toContainText('src/helper.rs');
  await expect(originRow).toHaveAttribute('aria-current','location');
  await expect.poll(()=>page.evaluate(()=>window.getSelection()?.toString())).toContain('panic!');
  await toggle.click();
  await expect(page.locator('.trace')).not.toHaveAttribute('reversed');
  await expect(rows).toHaveText(forward);
  await expect.poll(()=>entries.evaluateAll(elements=>elements.map(element=>(element as HTMLLIElement).value))).toEqual(numbers);
  await expect(originRow).toHaveAttribute('aria-current','location');
  await expect(entry).not.toHaveAttribute('aria-current','location');
  await page.getByRole('button',{name:'← Back',exact:true}).click();
  await expect(page.locator('.filename')).toContainText('src/lib.rs');
  await expect(entry).toHaveAttribute('aria-current','location');
  await page.locator('.cm-content').focus();
  await page.keyboard.press('ControlOrMeta+Home');
  await expect(page.locator('.trace button[aria-current="location"]')).toHaveCount(0);
  await clickIdentifier(page,'helper::danger()', 'danger');
  await expect(entry).toHaveAttribute('aria-current','location');
});

test('call sites select exact ranges and editor definition navigation crosses files',async({page})=>{
  await stop();
  await writeFile(join(dir,'src/lib.rs'),'\ufeff// λ before call sites\r\nmod helper;\r\npub fn risky() {\r\n    helper::danger();\r\n}\r\n');
  await writeFile(join(dir,'src/helper.rs'),'// λ before the definition\npub fn danger() {\n    panic!("navigation test");\n}\n');
  await launch();await selectFinding(page);
  const trace=page.locator('.trace button').filter({hasText:'risky'}).first();
  await trace.click();
  await expect(page.locator('.filename')).toContainText('src/lib.rs');
  await expect.poll(()=>page.evaluate(()=>window.getSelection()?.toString())).toContain('helper::danger()');
  await trace.click();
  await expect.poll(()=>page.evaluate(()=>window.getSelection()?.toString())).toContain('helper::danger()');
  await expect(page.getByRole('button',{name:'↻ Reanalyze',exact:true})).toBeEnabled();
  await expect(page.locator('.navigation-status')).toContainText('Rust navigation ready',{timeout:30000});
  const clickDanger=(modifier=false)=>clickIdentifier(page,'helper::danger()', 'danger',modifier);
  await clickDanger(true);
  await expect(page.locator('.filename')).toContainText('src/helper.rs',{timeout:30000});
  await expect(page.locator('.trace button[aria-current="location"]')).toHaveCount(0);
  await page.getByRole('button',{name:'← Back',exact:true}).click();
  await expect(page.locator('.filename')).toContainText('src/lib.rs');
  await expect(trace).toHaveAttribute('aria-current','location');
  await clickDanger();await page.keyboard.press('F12');
  await expect(page.locator('.filename')).toContainText('src/helper.rs');
  await page.getByRole('button',{name:'← Back',exact:true}).click();
  await expect(page.locator('.filename')).toContainText('src/lib.rs');
  await page.locator('.cm-content').focus();await page.keyboard.press('ControlOrMeta+Home');
  await page.keyboard.press('ArrowRight'); // Keep the BOM at the start of the file.
  await page.keyboard.insertText('// draft navigation\n');
  await expect(page.getByLabel('Source save status')).toHaveText('Unsaved changes');
  await clickDanger(true);
  await expect(page.locator('.filename')).toContainText('src/helper.rs');
  expect(await readFile(join(dir,'src/lib.rs'),'utf8')).toContain('draft navigation');
});


test('language server failure preserves audit navigation',async({page})=>{
  await page.route('**/api/v1/lsp/events?*',route=>route.fulfill({status:503,body:'rust-analyzer is not installed'}));
  await selectFinding(page);
  await expect(page.locator('.navigation-status')).toContainText('Rust navigation unavailable');
  await page.getByRole('button',{name:'Report root',exact:true}).click();
  await expect(page.locator('.filename')).toContainText('src/lib.rs');
  await expect(page.locator('.cm-editor')).toBeVisible();
  const point=await identifierBounds(page,'pub fn risky()', 'risky');
  await page.mouse.move(point.x,point.y);await page.keyboard.down(process.platform==='darwin'?'Meta':'Control');
  await expect(page.locator('.cm-definition-link')).toHaveCount(0);
  await page.keyboard.up(process.platform==='darwin'?'Meta':'Control');
});

test('dependency source and definition destinations are readable but not writable',async({page})=>{
  const dependency=await mkdtemp(join(tmpdir(),'sniff-navigation-dep-'));
  try{
    await stop();await mkdir(join(dependency,'src'));
    await writeFile(join(dependency,'Cargo.toml'),'[package]\nname="navigation-dep"\nversion="0.1.0"\nedition="2024"\n');
    await writeFile(join(dependency,'src/lib.rs'),'// dependency declaration\npub fn danger() { panic!("dependency"); }\n');
    await writeFile(join(dir,'Cargo.toml'),`[package]\nname="audit-browser-fixture"\nversion="0.1.0"\nedition="2024"\n[workspace]\n[dependencies]\nnavigation-dep={path=${JSON.stringify(dependency)}}\n`);
    await writeFile(join(dir,'src/lib.rs'),'pub fn risky() {\n    navigation_dep::danger();\n}\n');
    await launch();await selectFinding(page);
    await page.getByRole('button',{name:'Effect source',exact:true}).click();
    await expect(page.locator('.buffer-state')).toContainText('Read-only dependency');
    await expect.poll(()=>page.evaluate(()=>window.getSelection()?.toString())).toContain('panic!');
    await page.locator('.trace button').filter({hasText:'risky'}).first().click();
    await expect(page.locator('.navigation-status')).toContainText('Rust navigation ready',{timeout:30000});
    await expect(page.locator('.filename')).toHaveText('src/lib.rs');
    const point=await identifierBounds(page,'navigation_dep::danger()', 'danger');
    await page.mouse.move(point.x,point.y);await page.keyboard.down(process.platform==='darwin'?'Meta':'Control');
    await expect(page.locator('.cm-definition-link')).toHaveText('danger');
    await page.keyboard.up(process.platform==='darwin'?'Meta':'Control');
    await expect(page.locator('.cm-definition-link')).toHaveCount(0);
    await clickIdentifier(page,'navigation_dep::danger()', 'danger');
    await page.keyboard.press('F12');
    await expect(page.locator('.filename')).toContainText(dependency,{timeout:30000});
    await expect(page.locator('.buffer-state')).toContainText('Read-only dependency');
    await expect(page.getByRole('button',{name:'Save draft',exact:true})).toHaveCount(0);
    await expect(page.locator('.cm-content')).toHaveAttribute('aria-readonly','true');
  }finally{await stop();await rm(dependency,{recursive:true,force:true});}
});


test('modifier hover marks only resolvable identifiers and clears stale cues',async({page})=>{
  await stop();
  await writeFile(join(dir,'src/lib.rs'),'\ufeffpub fn risky() {\r\n    // gefährlich in a comment\r\n    let _ = "gefährlich in a string";\r\n    gefährlich();\r\n}\r\nfn gefährlich() { panic!("test"); }\r\n');
  await launch();await selectFinding(page);
  await page.locator('.trace button').filter({hasText:'risky'}).first().click();
  await expect(page.getByRole('button',{name:'↻ Reanalyze',exact:true})).toBeEnabled();
  await expect(page.locator('.navigation-status')).toContainText('Rust navigation ready',{timeout:30000});
  const key=process.platform==='darwin'?'Meta':'Control';
  const link=page.locator('.cm-definition-link');
  const bounds=await identifierBounds(page,'    gefährlich();','gefährlich');
  await page.mouse.move(bounds.x,bounds.y);
  await expect(link).toHaveCount(0);
  let requests=0;
  page.on('request',request=>{if(request.url().includes('/lsp/messages') && request.postDataJSON()?.method==='textDocument/definition')requests++;});
  await page.keyboard.down(key); // Stationary pointer: no mousemove after keydown.
  await expect(link).toHaveText('gefährlich');
  await expect(link).toHaveCSS('cursor','pointer');
  await expect(link).toHaveCSS('text-decoration-line','underline');
  await expect(link).toHaveCSS('color','rgb(36, 92, 63)');
  expect(requests).toBe(1);
  await page.keyboard.up(key);await expect(link).toHaveCount(0);
  await page.keyboard.down(key);await expect(link).toHaveText('gefährlich');
  expect(requests).toBe(1); // The unchanged identifier reuses its resolved destination.
  for(const line of ['// gefährlich in a comment','let _ = "gefährlich in a string";']){
    const point=await identifierBounds(page,line,'gefährlich');await page.mouse.move(point.x,point.y);
    await expect(link).toHaveCount(0);
  }
  expect(requests).toBe(1);
  await page.mouse.move(bounds.x,bounds.y);await expect(link).toHaveText('gefährlich');
  await page.screenshot({path:join(repo,'target/audit-definition-hover.png'),fullPage:true});
  await page.mouse.click(bounds.x,bounds.y);
  await page.keyboard.up(key);await expect(link).toHaveCount(0);
  expect(requests).toBe(1); // Clicking the cue uses the same lookup.
  await expect.poll(()=>page.locator('.cm-activeLine').textContent()).toContain('fn gefährlich');
  await page.getByRole('button',{name:'← Back',exact:true}).click();
  await expect(page.getByRole('button',{name:'↻ Reanalyze',exact:true})).toBeEnabled();
  await page.mouse.move(bounds.x,bounds.y);await page.keyboard.down(key);await expect(link).toHaveText('gefährlich');
  await page.evaluate(()=>window.dispatchEvent(new Event('blur')));await expect(link).toHaveCount(0);
  await page.keyboard.up(key);
  // Editing clears both the decoration and the cached result; an unresolved name gets no cue.
  await page.locator('.cm-content').focus();await page.keyboard.press('ControlOrMeta+End');
  await page.keyboard.insertText('\nfn draft() { nonexistent_symbol(); }\n');
  const missing=await identifierBounds(page,'fn draft()', 'nonexistent_symbol');
  let release!:()=>void,seen!:()=>void;
  const held=new Promise<void>(resolve=>release=resolve),requested=new Promise<void>(resolve=>seen=resolve);
  await page.route('**/api/v1/lsp/messages?*',async route=>{
    if(route.request().postDataJSON()?.method==='textDocument/definition'){seen();await held;}
    await route.continue();
  });
  const delayed=await identifierBounds(page,'    gefährlich();','gefährlich');
  await page.mouse.move(delayed.x,delayed.y);await page.keyboard.down(key);await requested;
  await expect(link).toHaveCount(0);
  const delivered=page.waitForResponse(response=>response.url().includes('/lsp/messages') && response.request().postDataJSON()?.method==='textDocument/definition');
  await page.mouse.move(10,10);release();await delivered;
  await page.keyboard.up(key);
  await expect(link).toHaveCount(0);
  await page.unroute('**/api/v1/lsp/messages?*');
  await page.mouse.move(missing.x,missing.y);await page.keyboard.down(key);
  // Allow the real null response to settle; no underline may appear.
  await page.waitForTimeout(300);
  await expect(link).toHaveCount(0);await page.keyboard.up(key);
});

// Control LSP timing independently of machine speed and rust-analyzer indexing.
async function controlledNavigation(page:any){
  await page.addInitScript(()=>{
    const original=window.fetch.bind(window);
    let stream:ReadableStreamDefaultController<Uint8Array>;
    const encoder=new TextEncoder();
    const send=(message:unknown)=>stream.enqueue(encoder.encode('data: '+JSON.stringify(message)+'\n\n'));
    const control=(window as any).navigationTest={requests:0,empty:true,hold:false,pending:[] as any[],
      status(quiescent:boolean){send({jsonrpc:'2.0',method:'experimental/serverStatus',params:{health:'ok',quiescent}});},
      release(){for(const message of this.pending)send(message);this.pending=[];},
    };
    window.fetch=async(input,init)=>{
      const url=String(input);
      if(url.includes('/lsp/events?'))return new Response(new ReadableStream({start(controller){stream=controller;}}),{headers:{'Content-Type':'text/event-stream'}});
      if(!url.includes('/lsp/messages?'))return original(input,init);
      const message=JSON.parse(String(init?.body));
      if(message.method==='initialize')send({jsonrpc:'2.0',id:message.id,result:{capabilities:{definitionProvider:true,textDocumentSync:2}}});
      else if(message.method==='initialized')control.status(true);
      else if(message.method==='textDocument/definition'){
        control.requests++;
        const response={jsonrpc:'2.0',id:message.id,result:control.empty?null:{uri:message.params.textDocument.uri,range:{start:{line:3,character:7},end:{line:3,character:12}}}};
        if(control.hold)control.pending.push(response);else send(response);
      }
      return new Response('{}',{headers:{'Content-Type':'application/json'}});
    };
  });
}

test('definition misses recover and indexing refreshes a stationary generic-method hover',async({page})=>{
  await stop();
  await writeFile(join(dir,'src/lib.rs'),'pub struct Domain<T>(T);\nimpl<T> Domain<T> {\n    /// # Panics\n    fn index(&self) { panic!("test"); }\n    pub fn ensure(&self) { self.index(); }\n}\n');
  await launch();await controlledNavigation(page);await selectFinding(page);
  await page.getByRole('button',{name:'Report root',exact:true}).click();
  await expect(page.locator('.navigation-status')).toContainText('Rust navigation ready');
  const point=await identifierBounds(page,'self.index()', 'index');
  const key=process.platform==='darwin'?'Meta':'Control';
  await page.mouse.move(point.x,point.y);
  // Trace positioning can deliver its scroll after mousemove and before keydown.
  await page.locator('.cm-scroller').evaluate(element=>element.dispatchEvent(new Event('scroll')));
  await page.keyboard.down(key);
  await expect.poll(()=>page.evaluate(()=>(window as any).navigationTest.requests)).toBe(1);
  await expect(page.locator('.cm-definition-link')).toHaveCount(0);
  await page.evaluate(()=>{(window as any).navigationTest.empty=false;});
  await page.keyboard.up(key);await page.keyboard.down(key);
  await expect(page.locator('.cm-definition-link')).toHaveText('index');
  await page.mouse.click(point.x,point.y);await page.keyboard.up(key);
  await expect.poll(()=>page.locator('.cm-activeLine').textContent()).toContain('fn index');
  await page.getByRole('button',{name:'← Back',exact:true}).click();
  const next=await identifierBounds(page,'self.index()', 'index');
  await page.evaluate(()=>{const c=(window as any).navigationTest;c.empty=true;c.status(false);});
  await page.mouse.move(next.x,next.y);await page.keyboard.down(key);
  await expect.poll(()=>page.evaluate(()=>(window as any).navigationTest.requests)).toBe(3);
  await page.evaluate(()=>{const c=(window as any).navigationTest;c.empty=false;c.status(true);});
  await expect(page.locator('.cm-definition-link')).toHaveText('index');
  await page.keyboard.up(key);
  await clickIdentifier(page,'self.index()', 'index');await page.keyboard.press('F12');
  await expect.poll(()=>page.locator('.cm-activeLine').textContent()).toContain('fn index');
  await page.getByRole('button',{name:'← Back',exact:true}).click();
  // A result from before an indexing transition must not redirect the editor.
  await page.evaluate(()=>{const c=(window as any).navigationTest;c.hold=true;c.status(false);});
  await clickIdentifier(page,'self.index()', 'index');await page.keyboard.press('F12');
  await expect.poll(()=>page.evaluate(()=>(window as any).navigationTest.pending.length)).toBe(1);
  await page.evaluate(()=>{const c=(window as any).navigationTest;c.status(true);c.release();});
  await expect(page.locator('.navigation-status')).toContainText('Rust navigation ready');
  await expect(page.locator('.cm-activeLine')).toContainText('self.index()');
});

test('editing invalidates a pending definition and retries against the new document',async({page})=>{
  await stop();
  await writeFile(join(dir,'src/lib.rs'),'pub fn risky() { danger(); }\n\n// destination\nfn danger() { panic!("test"); }\n');
  await launch();await controlledNavigation(page);await selectFinding(page);
  await page.getByRole('button',{name:'Report root',exact:true}).click();
  await expect(page.locator('.navigation-status')).toContainText('Rust navigation ready');
  await page.evaluate(()=>{const c=(window as any).navigationTest;c.empty=false;c.hold=true;});
  await clickIdentifier(page,'pub fn risky()', 'danger');await page.keyboard.press('F12');
  await expect.poll(()=>page.evaluate(()=>(window as any).navigationTest.pending.length)).toBe(1);
  await page.keyboard.press('ControlOrMeta+End');await page.keyboard.insertText('// draft\n');
  await page.evaluate(()=>{const c=(window as any).navigationTest;c.release();c.hold=false;});
  await expect(page.locator('.cm-activeLine')).not.toContainText('fn danger');
  await clickIdentifier(page,'pub fn risky()', 'danger');await page.keyboard.press('F12');
  await expect.poll(()=>page.locator('.cm-activeLine').textContent()).toContain('fn danger');
  await expect.poll(()=>page.evaluate(()=>(window as any).navigationTest.requests)).toBe(2);
  await page.keyboard.press('ControlOrMeta+s');
  await expect.poll(()=>readFile(join(dir,'src/lib.rs'),'utf8')).toContain('// draft');
});

for(const width of [1440,320]) {
  test(`definition navigation targets the call beneath Justify here at width ${width}`,async({page})=>{
    await stop();
    const source='pub struct Domain<T>(T);\nimpl<T> Domain<T> {\n    /// # Panics\n    /// Always panics.\n    pub fn index(&self, _value: &T) { panic!("test"); }\n}\nfn nearby(domain: &Domain<u32>) {\n    domain.index(&1);\n}\npub fn selected(domain: &Domain<u32>) {\n    domain.index(&2);\n}\n';
    await writeFile(join(dir,'src/lib.rs'),source);await launch();
    await page.setViewportSize({width,height:960});await page.goto(url);
    await page.locator('.group').first().click();
    const finding=page.locator('.finding').filter({has:page.locator('strong',{hasText:'::selected'})});
    await expect(finding).toBeVisible();await expect(page.locator('.status')).not.toContainText('running');await finding.click();
    await page.getByRole('button',{name:'Report root',exact:true}).click();
    await expect(page.locator('.navigation-status')).toContainText('Rust navigation ready',{timeout:30000});
    const prompt=page.locator('.inline-prompt').filter({has:page.getByRole('button',{name:'Justify here'})});
    await expect(prompt).toBeVisible();
    // Select by the prompt's adjacent source line, never the first similar call.
    await expect(prompt.locator('xpath=following-sibling::*[1]')).toContainText('domain.index(&2)');
    if(width===320){
      const button=await prompt.locator('button').boundingBox(),hint=await prompt.locator('span').boundingBox();
      expect(hint!.y).toBeGreaterThanOrEqual(button!.y+button!.height);
    }
    const requests:any[]=[];
    page.on('request',request=>{if(request.url().includes('/lsp/messages') && request.postDataJSON()?.method==='textDocument/definition')requests.push(request.postDataJSON().params.position);});
    const point=await identifierBounds(page,'domain.index(&2)', 'index');
    const key=process.platform==='darwin'?'Meta':'Control';
    await page.mouse.move(point.x,point.y);await page.keyboard.down(key);
    await expect(page.locator('.cm-definition-link')).toHaveText('index');
    expect(requests.at(-1)).toEqual({line:10,character:11});
    await page.mouse.click(point.x,point.y);await page.keyboard.up(key);
    await expect(page.locator('.cm-activeLine')).toContainText('pub fn index(');
    await page.getByRole('button',{name:'← Back',exact:true}).click();
    await expect(page.locator('.cm-activeLine')).toContainText('domain.index(&2)');
    const callLine=page.locator('.cm-line').filter({hasText:'domain.index(&2)'});
    await callLine.scrollIntoViewIfNeeded();
    const cursor=await identifierBounds(page,'domain.index(&2)', 'index');
    const bounds=await callLine.boundingBox();
    // Locator clicks wait for Back's scrolling/layout to settle, unlike mouse.click.
    await callLine.click({position:{x:cursor.x-bounds!.x,y:cursor.y-bounds!.y}});
    await page.keyboard.press('F12');
    await expect(page.locator('.cm-activeLine')).toContainText('pub fn index(');
    await page.getByRole('button',{name:'← Back',exact:true}).click();
    await expect(page.locator('.cm-activeLine')).toContainText('domain.index(&2)');
  });
}

test('override prompts remain usable after source autosaves make the analysis stale',async({page})=>{
  const dependency=await mkdtemp(join(tmpdir(),'sniff-stale-override-'));
  try {
    await stop();await mkdir(join(dependency,'src'));
    await writeFile(join(dependency,'Cargo.toml'),'[package]\nname="stale-dep"\nversion="0.1.0"\nedition="2024"\n');
    const source='pub fn danger(flag: bool) {\n    assert!(flag);\n}\n';
    await writeFile(join(dependency,'src/lib.rs'),source);
    await writeFile(join(dir,'Cargo.toml'),`[package]\nname="audit-browser-fixture"\nversion="0.1.0"\nedition="2024"\n[workspace]\n[dependencies]\nstale-dep={path=${JSON.stringify(dependency)}}\n`);
    await writeFile(join(dir,'src/lib.rs'),'pub fn entry(flag: bool) { stale_dep::danger(flag); }\n');
    await launch();await selectFinding(page);
    await page.getByRole('button',{name:'Report root',exact:true}).click();
    await expect(page.locator('.filename')).toHaveText('src/lib.rs');
    await expect(page.locator('.cm-content')).not.toHaveAttribute('aria-readonly','true');
    await page.locator('.cm-content').focus();await page.keyboard.press('ControlOrMeta+Home');await page.keyboard.insertText('// root edit\n');
    await page.keyboard.press('ControlOrMeta+s');await expect(page.getByLabel('Source save status')).toHaveText('Saved');
    await expect(page.locator('.status')).toContainText('stale');
    await page.getByRole('button',{name:'Effect source',exact:true}).click();
    for(const label of ['Justify via override','Propagate obligations via override'])await expect(page.getByRole('button',{name:label,exact:true})).toBeVisible();
    await page.getByRole('button',{name:'Justify via override',exact:true}).click();
    await page.getByLabel('Override documentation').fill('// PANIC: The caller validates the flag.');
    await page.getByRole('dialog').getByRole('button',{name:'Save',exact:true}).click();
    await page.getByRole('button',{name:'Create & save',exact:true}).click();
    await expect(page.getByRole('button',{name:'Justified!',exact:true})).toBeVisible();
    expect(await readFile(join(dir,'sniff-test-overrides.toml'),'utf8')).toContain('The caller validates the flag.');
    expect(await readFile(join(dependency,'src/lib.rs'),'utf8')).toBe(source);
  } finally {await stop();await rm(dependency,{recursive:true,force:true});}
});

for(const action of ['Justify via override','Propagate obligations via override']) {
  for(const existing of [true,false]) {
    test(`dependency ${action} saves directly to ${existing?'existing':'new named'} override file`,async({page})=>{
      const dependency=await mkdtemp(join(tmpdir(),'sniff-override-dep-'));
      const source='// λ dependency\r\n#[inline]\r\n#[allow(\r\n    unused\r\n)]\r\npub fn danger(flag: bool) {\r\n    #[allow(unused)]\r\n    assert!(flag, "dependency");\r\n}\r\n';
      try {
        await stop();await mkdir(join(dependency,'src'));
        await writeFile(join(dependency,'Cargo.toml'),'[package]\nname="override-dep"\nversion="0.1.0"\nedition="2024"\n');
        await writeFile(join(dependency,'src/lib.rs'),source);
        await writeFile(join(dir,'Cargo.toml'),`[package]\nname="audit-browser-fixture"\nversion="0.1.0"\nedition="2024"\n[workspace]\n[dependencies]\noverride-dep={path=${JSON.stringify(dependency)}}\n`);
        await writeFile(join(dir,'src/lib.rs'),'pub fn entry(flag: bool) { override_dep::danger(flag); }\n');
        const original='# Preserve this comment\n[overrides]\n"unrelated::api" = "# Safety\\nExisting contract"\n';
        if(existing){
          await writeFile(join(dir,'sniff-test.toml'),'[contracts]\noverride-files=["one.toml","two.toml"]\n');
          for(const file of ['one.toml','two.toml'])await writeFile(join(dir,file),original);
        }
        await launch();await selectFinding(page);
        await expect(page.locator('.buffer-state')).toContainText('Read-only dependency');
        await expect(page.getByRole('button',{name:'Review diff',exact:true})).toHaveCount(0);
        await expect(page.getByRole('button',{name:'Discard draft',exact:true})).toHaveCount(0);
        const template=action.startsWith('Justify')?'// PANIC: ':'/// # Panics\n///\n/// ';
        const explanation=template+'The flag is checked by the caller.';
        const completed=action.startsWith('Justify')?'Justified!':'Obligation propagated!';
        const alternative=action.startsWith('Justify')?'Propagate obligations via override':'Justify via override';
        const dialog=page.getByRole('dialog');
        await page.getByRole('button',{name:action,exact:true}).click();
        await expect(dialog.getByLabel('Override documentation')).toHaveValue(template);
        await expect(dialog.getByLabel('Override documentation')).toBeFocused();
        if(existing&&action.startsWith('Justify')) {
          const handle=dialog.getByRole('button',{name:'Move override popup'});
          const initial=(await dialog.boundingBox())!;
          expect(initial.x+initial.width/2).toBeGreaterThan(1440/2);
          expect(await dialog.evaluate(el=>el.matches(':modal'))).toBe(false);
          const grip=(await handle.boundingBox())!;
          await page.mouse.move(grip.x+20,grip.y+10);await page.mouse.down();
          await page.mouse.move(grip.x-100,grip.y+90);await page.mouse.up();
          const moved=(await dialog.boundingBox())!;
          expect(moved.x).toBeCloseTo(initial.x-120,0);
          expect(moved.y).toBeCloseTo(initial.y+80,0);
          await handle.press('ArrowRight');
          expect((await dialog.boundingBox())!.x).toBeCloseTo(moved.x+20,0);
          const grip2=(await handle.boundingBox())!;
          await page.mouse.move(grip2.x+20,grip2.y+10);await page.mouse.down();
          await page.mouse.move(-1000,-1000);await page.mouse.up();
          expect((await dialog.boundingBox())!.x).toBe(16);
          expect((await dialog.boundingBox())!.y).toBe(16);
          const grip3=(await handle.boundingBox())!;
          await page.mouse.move(grip3.x+20,grip3.y+10);await page.mouse.down();
          await page.mouse.move(2000,2000);await page.mouse.up();
          const corner=(await dialog.boundingBox())!;
          expect(corner.x+corner.width).toBeLessThanOrEqual(1424);
          expect(corner.y+corner.height).toBeLessThanOrEqual(944);
          const draft=template+'Keep this unsaved explanation.';
          await dialog.getByLabel('Override documentation').fill(draft);
          await page.locator('.cm-content').focus();
          await page.keyboard.press('Escape');
          await expect(dialog).toBeVisible();
          await page.getByRole('button',{name:'Report root',exact:true}).click();
          await expect(page.locator('.filename')).toHaveText('src/lib.rs');
          await expect(dialog.getByLabel('Override documentation')).toHaveValue(draft);
          await page.getByRole('button',{name:'Effect source',exact:true}).click();
          await page.getByRole('button',{name:alternative,exact:true}).click();
          await expect(dialog).toHaveAccessibleName(action);
          await expect(dialog.getByLabel('Override documentation')).toHaveValue(draft);
          await expect(handle).toBeFocused();
          await page.setViewportSize({width:480,height:700});
          await expect(dialog).toBeInViewport();
          const narrow=(await dialog.boundingBox())!;
          expect(narrow.x).toBeGreaterThanOrEqual(16);
          expect(narrow.x+narrow.width).toBeLessThanOrEqual(464);
          await page.setViewportSize({width:1440,height:960});
          await dialog.getByLabel('Override documentation').fill(template);
          await dialog.getByLabel('Override documentation').focus();
        }
        await page.keyboard.insertText('Typed at the end.');
        await expect(dialog.getByLabel('Override documentation')).toHaveValue(template+'Typed at the end.');
        await dialog.getByRole('button',{name:'Cancel',exact:true}).click();
        await expect(page.locator('.draft')).toHaveCount(0);
        await page.getByRole('button',{name:action,exact:true}).click();
        await dialog.getByLabel('Override documentation').fill(explanation);
        if(existing)await dialog.getByLabel('Override file',{exact:true}).selectOption({index:1});
        const editorPosition=(await dialog.boundingBox())!;
        await dialog.getByRole('button',{name:'Save',exact:true}).click();
        let destination=join(dir,'two.toml');
        if(!existing){
          await expect(dialog).toHaveAccessibleName('Create override file');
          const filePosition=(await dialog.boundingBox())!;
          expect(filePosition.x).toBeCloseTo(editorPosition.x,0);
          expect(filePosition.y).toBeCloseTo(editorPosition.y,0);
          await expect(dialog.getByLabel('Override filename')).toHaveValue('sniff-test-overrides.toml');
          if(action.startsWith('Justify')){
            await page.setViewportSize({width:320,height:700});
            await expect(dialog.getByLabel('Override filename')).toBeInViewport();
            await expect(dialog.getByRole('button',{name:'Create & save',exact:true})).toBeInViewport();
            await page.screenshot({path:join(repo,'target/audit-override-filename.png'),fullPage:true});
            await page.setViewportSize({width:1440,height:960});
          }
          await dialog.getByRole('button',{name:'Cancel',exact:true}).click();
          await expect(dialog.getByLabel('Override documentation')).toHaveValue(explanation);
          await dialog.getByRole('button',{name:'Save',exact:true}).click();
          await dialog.getByLabel('Override filename').fill('');
          await expect(dialog.getByRole('button',{name:'Create & save',exact:true})).toBeDisabled();
          await writeFile(join(dir,'taken.toml'),'# keep existing file\n');
          await dialog.getByLabel('Override filename').fill('taken.toml');
          await dialog.getByRole('button',{name:'Create & save',exact:true}).click();
          await expect(dialog.getByRole('alert')).toContainText('already exists');
          expect(await readFile(join(dir,'taken.toml'),'utf8')).toBe('# keep existing file\n');
          await dialog.getByLabel('Override filename').fill('custom-overrides.toml');
          await dialog.getByRole('button',{name:'Create & save',exact:true}).click();
          destination=join(dir,'custom-overrides.toml');
        }
        await expect(dialog).not.toBeVisible();
        await expect(page.locator('.status')).toHaveText('complete · reanalysis needed');
        await expect(page.locator('.draft')).toHaveCount(0);
        await expect(page.getByRole('button',{name:completed,exact:true})).toBeVisible();
        const mark=action.startsWith('Justify')?'Justification saved':'Propagation saved';
        await expect(page.locator('.finding.selected').getByLabel(mark,{exact:true})).toBeVisible();
        await expect(page.locator('.group').getByLabel(mark,{exact:true})).toBeVisible();
        await page.getByRole('button',{name:'⇄ Invert effect',exact:true}).click();
        await expect(page.locator('.group').getByLabel(mark,{exact:true})).toBeVisible();
        await page.getByRole('button',{name:'⇄ Invert effect',exact:true}).click();
        await expect(page.getByRole('button',{name:alternative,exact:true})).toHaveCount(0);
        await expect(page.locator('footer')).toContainText(existing?'two.toml':'custom-overrides.toml');
        expect(await readFile(destination,'utf8')).toContain('The flag is checked by the caller.');
        expect(await readFile(join(dependency,'src/lib.rs'),'utf8')).toBe(source);
        if(existing)expect(await readFile(join(dir,'one.toml'),'utf8')).toBe(original);
        else expect(await readFile(join(dir,'sniff-test.toml'),'utf8')).toContain('custom-overrides.toml');
        // Reopen and edit immediately, before any reanalysis.
        await page.getByRole('button',{name:completed,exact:true}).click();
        if(existing)await expect(dialog.getByLabel('Override file',{exact:true})).toHaveValue(/\/two\.toml$/);
        await expect(dialog.getByRole('button',{name:'Save draft',exact:true})).toHaveCount(0);
        await dialog.getByLabel('Override documentation').fill(template+'A revised explanation.');
        await dialog.getByRole('button',{name:'Save',exact:true}).click();
        await expect(dialog).not.toBeVisible();
        const saved=await readFile(destination,'utf8');
        expect(saved).toContain('A revised explanation.');
        expect(saved).not.toContain('The flag is checked by the caller.');
        if(existing){expect(saved).toContain('# Preserve this comment');expect(saved).toContain('unrelated::api');}
        // Concurrent edits reject the save and preserve the user's text.
        await page.getByRole('button',{name:completed,exact:true}).click();
        await dialog.getByLabel('Override documentation').fill(template+'Unsaved conflicting explanation.');
        await writeFile(destination,saved+'# concurrent edit\n');
        await dialog.getByRole('button',{name:'Save',exact:true}).click();
        await expect(dialog.getByRole('alert')).toContainText('Override file changed');
        await expect(dialog.getByLabel('Override documentation')).toHaveValue(template+'Unsaved conflicting explanation.');
        expect(await readFile(destination,'utf8')).toBe(saved+'# concurrent edit\n');
        await dialog.getByRole('button',{name:'Cancel',exact:true}).click();
        await page.reload();await selectFinding(page);
        await expect(page.getByRole('button',{name:completed,exact:true})).toBeVisible();
        await page.getByRole('button',{name:completed,exact:true}).click();
        await expect(dialog.getByLabel('Override documentation')).toHaveValue(template+'A revised explanation.');
        await dialog.getByRole('button',{name:'Cancel',exact:true}).click();
        expect(await readFile(join(dependency,'src/lib.rs'),'utf8')).toBe(source);
        // External deletion must remove completion metadata without a page reload.
        await page.reload();await selectFinding(page);
        await expect(page.getByRole('button',{name:completed,exact:true})).toBeVisible();
        const displayedSource=await page.locator('.cm-line').allTextContents();
        await writeFile(destination,'');
        await expect(page.getByRole('button',{name:completed,exact:true})).toHaveCount(0);
        await expect(page.getByRole('button',{name:action,exact:true})).toBeVisible();
        await expect(page.locator('.status')).toContainText('stale');
        await expect(page.locator('.finding-list').getByLabel(mark,{exact:true})).toHaveCount(0);
        expect(await page.locator('.cm-line').allTextContents()).toEqual(displayedSource);
        await page.getByRole('button',{name:'↻ Reanalyze',exact:true}).click();
        await expect(page.locator('.status')).toHaveText('complete');
        if(!await page.locator('.finding').count())await page.locator('.group').first().click();
        await page.locator('.finding').first().click();
        await expect(page.getByRole('button',{name:completed,exact:true})).toHaveCount(0);
      } finally {await stop();await rm(dependency,{recursive:true,force:true});}
    });
  }
}

for(const action of ['Justify via override','Propagate obligations via override']) {
  test(`dependency ${action} can be removed with confirmation`,async({page})=>{
    const dependency=await mkdtemp(join(tmpdir(),'sniff-remove-override-'));
    const source='pub fn danger(flag: bool) { assert!(flag); }\n';
    try {
      await stop();await mkdir(join(dependency,'src'));
      await writeFile(join(dependency,'Cargo.toml'),'[package]\nname="remove-dep"\nversion="0.1.0"\nedition="2024"\n');
      await writeFile(join(dependency,'src/lib.rs'),source);
      await writeFile(join(dir,'Cargo.toml'),`[package]\nname="audit-browser-fixture"\nversion="0.1.0"\nedition="2024"\n[workspace]\n[dependencies]\nremove-dep={path=${JSON.stringify(dependency)}}\n`);
      await writeFile(join(dir,'src/lib.rs'),'pub fn entry(flag: bool) { remove_dep::danger(flag); }\n');
      const original='# Keep comment\n[overrides]\n"unrelated::api" = "# Safety\\nExisting contract"\n';
      await writeFile(join(dir,'sniff-test.toml'),'[contracts]\noverride-files=["saved.toml","other.toml"]\n');
      for(const file of ['saved.toml','other.toml'])await writeFile(join(dir,file),original);
      await launch();await selectFinding(page);
      const completed=action.startsWith('Justify')?'Justified!':'Obligation propagated!';
      const mark=action.startsWith('Justify')?'Justification saved':'Propagation saved';
      const text=action.startsWith('Justify')?'// PANIC: Checked by caller.':'/// # Panics\n/// Checked by caller.';
      const dialog=page.getByRole('dialog');
      await page.getByRole('button',{name:action,exact:true}).click();
      await expect(dialog.getByRole('button',{name:'Remove override',exact:true})).toHaveCount(0);
      await dialog.getByLabel('Override documentation').fill(text);
      await dialog.getByRole('button',{name:'Save',exact:true}).click();
      await page.getByRole('button',{name:completed,exact:true}).click();
      await dialog.getByLabel('Override documentation').fill(text+' Unsaved change.');
      await dialog.getByLabel('Override file',{exact:true}).selectOption({index:1});
      await page.setViewportSize({width:320,height:700});
      await expect(dialog.getByRole('button',{name:'Remove override',exact:true})).toBeInViewport();
      await dialog.getByRole('button',{name:'Remove override',exact:true}).click();
      await expect(dialog).toContainText('saved.toml');
      await expect(dialog.getByRole('button',{name:'Confirm removal',exact:true})).toBeInViewport();
      expect(await dialog.evaluate(element=>element.scrollWidth<=element.clientWidth)).toBe(true);

      await dialog.getByRole('button',{name:'Cancel',exact:true}).click();
      await page.setViewportSize({width:1440,height:960});
      await expect(dialog.getByLabel('Override documentation')).toHaveValue(text+' Unsaved change.');
      expect(await readFile(join(dir,'saved.toml'),'utf8')).toContain('Checked by caller.');
      // Conflicting writes must leave the popup and saved contribution intact.
      const saved=await readFile(join(dir,'saved.toml'),'utf8');
      await writeFile(join(dir,'saved.toml'),saved+'# concurrent edit\n');
      await dialog.getByRole('button',{name:'Remove override',exact:true}).click();
      await dialog.getByRole('button',{name:'Confirm removal',exact:true}).click();
      await expect(dialog.getByRole('alert')).toContainText('Override file changed');
      expect(await readFile(join(dir,'saved.toml'),'utf8')).toBe(saved+'# concurrent edit\n');
      await dialog.getByRole('button',{name:'Cancel',exact:true}).click();
      await dialog.getByRole('button',{name:'Cancel',exact:true}).click();
      await page.getByRole('button',{name:completed,exact:true}).click();
      await dialog.getByLabel('Override documentation').fill(text+' Unsaved final explanation.');
      await dialog.getByLabel('Override file',{exact:true}).selectOption({index:1});
      await dialog.getByRole('button',{name:'Remove override',exact:true}).click();
      await dialog.getByRole('button',{name:'Confirm removal',exact:true}).click();
      await expect(dialog).not.toBeVisible();
      await expect(page.getByRole('button',{name:completed,exact:true})).toHaveCount(0);
      await expect(page.getByRole('button',{name:action,exact:true})).toBeVisible();
      await expect(page.locator('.finding-list').getByLabel(mark,{exact:true})).toHaveCount(0);
      await expect(page.locator('.group').getByLabel(mark,{exact:true})).toHaveCount(0);
      const remaining=await readFile(join(dir,'saved.toml'),'utf8');
      expect(remaining).not.toContain('Checked by caller.');
      expect(remaining).toContain('# Keep comment');expect(remaining).toContain('unrelated::api');
      expect(await readFile(join(dir,'other.toml'),'utf8')).toBe(original);
      expect(await readFile(join(dependency,'src/lib.rs'),'utf8')).toBe(source);
      await page.reload();await selectFinding(page);
      await expect(page.getByRole('button',{name:completed,exact:true})).toHaveCount(0);
    } finally {await stop();await rm(dependency,{recursive:true,force:true});}
  });
}

test('file groups start collapsed and retain independent expansion and selection',async({page})=>{
  await stop();
  await writeFile(join(dir,'src/lib.rs'),'pub mod other;\npub fn first() { panic!("first"); }\n');
  await writeFile(join(dir,'src/other.rs'),'pub fn second() { panic!("second"); }\n');
  await launch();await page.goto(url);
  const groups=page.locator('.group');
  await expect(groups).toHaveCount(2);
  await expect(groups.first()).toHaveAttribute('aria-expanded','false');
  await expect(page.locator('.finding')).toHaveCount(0);
  await groups.first().focus();await page.keyboard.press('Enter');
  await expect(groups.first()).toHaveAttribute('aria-expanded','true');
  await page.locator('.finding').first().click();
  await expect(page.locator('.cm-editor')).toBeVisible();
  const filename=await page.locator('.filename').textContent();
  await groups.nth(1).click();
  await expect(groups.first()).toHaveAttribute('aria-expanded','true');
  await expect(groups.nth(1)).toHaveAttribute('aria-expanded','true');
  await groups.first().click();
  await page.screenshot({path:join(repo,'target/audit-file-groups.png'),fullPage:true});
  await expect(page.locator('.filename')).toHaveText(filename!);
  await expect(page.getByLabel('Selected effect',{exact:true})).toBeVisible();
  await page.getByLabel('Search findings',{exact:true}).fill('other.rs');
  await expect(groups).toHaveCount(1);
  await expect(groups.first()).toHaveAttribute('aria-expanded','true');
  await expect(groups.first().locator('.group-count')).toHaveText('1');
  await page.getByLabel('Search findings',{exact:true}).fill('no-such-file');
  await expect(page.getByText('No matching findings.',{exact:true})).toBeVisible();
});


test('inverted sources retain complete report counts during source-only search',async({page})=>{
  await stop();
  await writeFile(join(dir,'src/lib.rs'),`pub fn isolated_caller() { panic!("isolated"); }
fn shared_source() { panic!("shared"); }
pub fn first_caller() { shared_source(); }
pub fn second_caller() { shared_source(); }
`);
  await launch();await page.goto(url);
  await expect(page.locator('.status')).toHaveText('complete');
  await expect(page.locator('.group')).toHaveCount(1);
  await page.locator('.group').click();
  const first=page.locator('.finding').filter({has:page.locator('strong',{hasText:'::first_caller'})});
  await first.click();
  await expect(page.locator('.cm-editor')).toBeVisible();
  await page.locator('.cm-content').click();await page.keyboard.press('ControlOrMeta+Home');
  await page.keyboard.insertText('// audit draft retained across grouping changes\n');
  await page.keyboard.press('ControlOrMeta+s');
  const toggle=page.getByRole('button',{name:'Invert effect'});
  await toggle.click();await expect(toggle).toHaveAttribute('aria-pressed','true');
  await expect(page.locator('.group')).toHaveCount(2);
  const groups=page.locator('.finding-list > section');
  await expect(groups.first().locator('.group-count')).toHaveText('2');
  await expect(groups.last().locator('.group-count')).toHaveText('1');
  await groups.first().locator('.group').click();
  await expect(groups.first().locator('.finding')).toHaveCount(2);
  await expect(page.locator('.finding.selected strong')).toContainText('::first_caller');
  const search=page.getByRole('textbox',{name:'Search effect sources'});
  await search.fill('shared_source');
  await expect(page.locator('.group')).toHaveCount(1);
  await expect(page.locator('.group-count')).toHaveText('2');
  await expect(page.locator('.finding')).toHaveCount(2);
  await search.fill('first_caller');await expect(page.locator('.group')).toHaveCount(0);
  await search.fill('shared_source');
  await expect(page.locator('.group-count')).toHaveText('2');
  await page.locator('.finding').filter({has:page.locator('strong',{hasText:'::second_caller'})}).click();
  await expect(page.locator('.finding.selected strong')).toContainText('::second_caller');
  await expect(page.locator('.cm-content')).toContainText('// audit draft retained');
  const traceLength=await page.locator('.trace li').count();
  await expect(page.locator('.trace')).toHaveAttribute('reversed','');
  expect(await page.locator('.trace li').evaluateAll(elements=>elements.map(element=>(element as HTMLLIElement).value)))
    .toEqual(Array.from({length:traceLength},(_,i)=>traceLength-i));
  await expect(page.locator('.trace button').last()).toContainText('::second_caller');
  await search.fill('');await toggle.click();
  await expect(toggle).toHaveAttribute('aria-pressed','false');
  await expect(page.locator('.group')).toHaveCount(1);
  await expect(page.locator('.finding')).toHaveCount(3);
  await expect(page.locator('.finding.selected strong')).toContainText('::second_caller');
  await expect(page.locator('.draft')).toHaveCount(0);
  await toggle.click();await expect(page.locator('.group')).toHaveCount(2);
  await expect(page.locator('.finding')).toHaveCount(2);
  await page.screenshot({path:join(repo,'target/audit-inverted-sources.png'),fullPage:true});
});


for(const length of [0,1]) {
  test(`trace inversion handles ${length} entries`,async({page})=>{
    await page.route('**/api/v1/finding?*',async route=>{
      const response=await route.fetch(),finding=await response.json();
      finding.audit.trace=finding.audit.trace.slice(0,length);
      await route.fulfill({response,json:finding});
    });
    await selectFinding(page);
    const trace=page.locator('.trace'),entries=trace.locator('li');
    await expect(entries).toHaveCount(length);
    const forward=await entries.allTextContents();
    const toggle=page.getByRole('button',{name:'Invert effect'});
    await toggle.click();
    await expect(trace).toHaveAttribute('reversed','');
    await expect(entries).toHaveCount(length);
    await expect(entries).toHaveText(forward);
    if(length)await expect(entries).toHaveAttribute('value','1');
    await toggle.click();
    await expect(trace).not.toHaveAttribute('reversed');
    await expect(entries).toHaveText(forward);
  });
}

for(const width of [1440,900]) {
  test(`panels resize at ${width}px`,async({page})=>{
    await page.setViewportSize({width,height:900});
    await selectFinding(page);
    for(const side of ['findings','details']) {
      const panel=page.locator(`#${side}-panel`);
      const divider=page.getByRole('separator',{name:`Resize ${side} panel`});
      const before=(await panel.boundingBox())!;
      const handle=(await divider.boundingBox())!;
      const vertical=side==='details'&&width===900;
      await page.mouse.move(handle.x+handle.width/2,handle.y+handle.height/2);
      await page.mouse.down();
      await page.mouse.move(handle.x+handle.width/2+(vertical?0:side==='findings'?40:-40),handle.y+handle.height/2+(vertical?-40:0));
      await page.mouse.up();
      const after=(await panel.boundingBox())!;
      expect(vertical?after.height:after.width).toBeCloseTo((vertical?before.height:before.width)+40,0);
      await divider.focus();await page.keyboard.press(vertical?'ArrowUp':side==='findings'?'ArrowRight':'ArrowLeft');
      const resized=(await panel.boundingBox())!;
      expect(vertical?resized.height:resized.width).toBeCloseTo((vertical?after.height:after.width)+20,0);
    }
    await expect(page.locator('.cm-editor')).toBeVisible();
  });
}

for (const mode of ['native','namespace override','source override','trait declaration','standard library','safety','allocation','long contract','narrow layout','markdown links','generic prototype']) {
  test(`override justification shows the effective obligation from ${mode}`,async({page})=>{
    const dependency=await mkdtemp(join(tmpdir(),'sniff-obligation-dep-'));
    try {
      await stop();await mkdir(join(dependency,'src'));
      await writeFile(join(dependency,'Cargo.toml'),'[package]\nname="obligation-dep"\nversion="0.1.0"\nedition="2024"\n');
      const effect=mode==='safety'?'safety':mode==='allocation'?'allocation':'panic';
      const heading=effect==='safety'?'Safety':effect==='allocation'?'Allocations':'Panics';
      const marker=effect==='safety'?'SAFETY':effect==='allocation'?'ALLOCATION':'PANIC';
      const section=`# ${heading}\nThe flag must be true. λ\n\n- **valid**: supply a valid flag with \`true\`.\n- Preserve *caller invariants*.\n\n> Check the condition before calling.\n\n## Details\n`+(mode==='long contract'?'A long caller obligation.\n\n'.repeat(80):'')+(mode==='markdown links'?'[External reference](https://example.com/contract) · [Relative reference](../other.html) · [Rustdoc reference](struct.Widget.html) · [Unresolved item][Widget] · [Unsafe link](javascript:alert(1))\n\n![Diagram description](https://example.com/diagram.png)\n\n<span data-obligation-html="true">Inline HTML text.</span>\n\n<script>window.obligationScriptRan=true;</script>\n\n':'')+'```rust\n# Examples inside code\n```';
      const docs='Overview text.\n\n'+section+'\n\n# Examples\nUnrelated example text.';
      const comments=docs.split('\n').map(line=>'/// '+line).join('\n');
      const native=effect==='safety'
        ?`pub fn relay(flag: bool) { unsafe { danger(flag); } }\n${comments}\nunsafe fn danger(_flag: bool) {}\n`
        :`pub fn relay(flag: bool) { danger(flag); }\n${comments}\nfn danger(_flag: bool) {}\n`;
      const genericPrototype="pub(crate) fn danger<'a, T, const N: usize>(values: &'a [T; { N }]) -> &'a [T; { N }]\nwhere\n    T: Copy,\n    [(); { N }]: Copy,";
      const source=mode==='generic prototype'
        ?`pub fn relay(flag: bool) { let _ = danger(&[u8::from(flag); 2]); }\n${comments}\n${genericPrototype}\n{ values }\n`
        :mode==='trait declaration'
        ?`pub trait Contract {\n${comments}\nfn danger(flag: bool);\n}\nstruct Implementation;\nimpl Contract for Implementation { fn danger(_flag: bool) {} }\npub fn relay(flag: bool) { Implementation::danger(flag); }\n`
        :mode==='standard library'
        ?'pub fn relay(flag: bool) { let _ = [0].get(usize::from(flag)).unwrap(); }\n'
        :native;
      await writeFile(join(dependency,'src/lib.rs'),source);
      await writeFile(join(dir,'Cargo.toml'),`[package]\nname="audit-browser-fixture"\nversion="0.1.0"\nedition="2024"\n[workspace]\n[dependencies]\nobligation-dep={path=${JSON.stringify(dependency)}}\n`);
      await writeFile(join(dir,'src/lib.rs'),'pub fn entry(flag: bool) { obligation_dep::relay(flag); }\n');
      if(mode.includes('override')) {
        const replacement='# Panics\nEffective override condition.\n\n## Details\nUse the replacement contract.\n\n# Examples\nUnrelated override example.';
        const line=native.split('\n').findIndex(line=>line.startsWith('fn danger'))+1;
        const entry=mode==='namespace override'
          ?`[overrides]\n"obligation_dep::danger" = ${JSON.stringify(replacement)}\n`
          :`[overrides]\n"obligation_dep::danger" = "# Panics\\nSuperseded namespace condition."\n[overrides.crates."obligation_dep"."0.1.0"]\n"src/lib.rs:${line}:${line}" = ${JSON.stringify(replacement)}\n`;
        await writeFile(join(dir,'sniff-test.toml'),'[contracts]\noverride-files=["contracts.toml"]\n');
        await writeFile(join(dir,'contracts.toml'),entry);
      }
      await launch(effect);
      if(mode==='long contract')await page.setViewportSize({width:900,height:700});
      if(mode==='narrow layout')await page.setViewportSize({width:320,height:700});
      await page.goto(url);
      await page.getByLabel('Finding class',{exact:true}).selectOption('documented-obligation');
      await page.locator('.group').first().click();await page.locator('.finding').first().click();
      await page.getByRole('button',{name:'Justify via override',exact:true}).click();
      const dialog=page.getByRole('dialog'),context=dialog.getByRole('region',{name:'Obligation',exact:true});
      await expect(context).toBeVisible();
      await expect(context.getByRole('heading',{name:'Obligation',exact:true})).toHaveCount(0);
      await expect(context.locator('.obligation-header')).toHaveCount(0);
      const prototype=context.getByLabel('Function prototype',{exact:true});
      if(mode==='standard library')await expect(prototype).toContainText(/fn unwrap\(self\)\s*->\s*T/);
      else await expect(prototype).toHaveText(mode==='generic prototype'?genericPrototype:mode==='trait declaration'?'fn danger(flag: bool);':mode==='safety'?'unsafe fn danger(_flag: bool)':'fn danger(_flag: bool)');
      // Verify stock CodeMirror colors without depending on generated CSS class names.
      await expect(prototype.locator('span').filter({hasText:/^fn$/})).toHaveCSS('color','rgb(119, 0, 136)');
      if(mode!=='standard library') {
        await expect(prototype.locator('span').filter({hasText:/^danger$/})).toHaveCSS('color','rgb(0, 0, 255)');
        if(mode==='generic prototype') {
          await expect(prototype.locator('span').filter({hasText:/^where$/})).toHaveCSS('color','rgb(119, 0, 136)');
          await expect(prototype.locator('span').filter({hasText:/^T$/}).first()).toHaveCSS('color','rgb(0, 136, 85)');
          await expect(prototype.locator('span').filter({hasText:/^'a$/}).first()).toHaveCSS('color','rgb(34, 85, 102)');
        } else {
          await expect(prototype.locator('span').filter({hasText:/^bool$/})).toHaveCSS('color','rgb(0, 136, 85)');
        }
        if(mode==='safety')await expect(prototype.locator('span').filter({hasText:/^unsafe$/})).toHaveCSS('color','rgb(119, 0, 136)');
      }
      const body=await context.getByRole('region',{name:'Obligation documentation',exact:true}).boundingBox();
      const declaration=await prototype.boundingBox();
      expect(declaration!.y).toBeGreaterThanOrEqual(body!.y+body!.height);
      if(mode==='generic prototype') {
        const selected=await prototype.evaluate(el=>{
          const selection=window.getSelection()!;
          const range=document.createRange();range.selectNodeContents(el);
          selection.removeAllRanges();selection.addRange(range);
          const text=selection.toString();selection.removeAllRanges();
          return text;
        });
        expect(selected).toBe(genericPrototype);
      }
      if(mode==='standard library') {
        await expect(context).toContainText('unwrap');
        await expect(context.getByRole('heading',{name:'Panics',exact:true})).toBeVisible();
        await expect(context).toContainText('None');
      } else {
        await expect(context).not.toContainText('obligation_dep::');
        await expect(context.getByRole('heading',{name:heading,exact:true,level:4})).toBeVisible();
        await expect(context.getByRole('heading',{name:'Details',exact:true})).toBeVisible();
        if(mode.includes('override')) {
          await expect(context).toContainText('Effective override condition.');
          await expect(context).toContainText('Use the replacement contract.');
        } else {
          await expect(context.locator('li strong')).toHaveText('valid');
          await expect(context.locator('li em')).toHaveText('caller invariants');
          await expect(context.locator('li code')).toHaveText('true');
          await expect(context.locator('blockquote')).toHaveText('Check the condition before calling.');
          await expect(context.locator('pre code.language-rust')).toHaveText('# Examples inside code\n');
        }
        await expect(context).not.toContainText('Unrelated');
        await expect(context).not.toContainText('Superseded');
      }
      await expect(dialog.getByLabel('Override documentation')).toBeFocused();
      if(mode==='long contract')expect(await context.getByRole('region',{name:'Obligation documentation',exact:true}).evaluate(el=>el.scrollHeight>el.clientHeight)).toBe(true);
      if(mode==='markdown links') {
        const external=context.getByRole('link',{name:'External reference',exact:true});
        await expect(external).toHaveAttribute('href','https://example.com/contract');
        await expect(external).toHaveAttribute('target','_blank');
        await expect(external).toHaveAttribute('rel','noopener noreferrer');
        await expect(context.getByRole('link')).toHaveCount(1);
        await expect(context).toContainText('Relative reference');
        await expect(context).toContainText('Rustdoc reference');
        await expect(context).toContainText('[Unresolved item][Widget]');
        await expect(context).toContainText('Diagram description');
        await expect(context.locator('img,script,[data-obligation-html]')).toHaveCount(0);
        expect(await page.evaluate(()=>Object.hasOwn(window,'obligationScriptRan'))).toBe(false);
      }
      if(mode==='narrow layout') {
        await expect(dialog.getByRole('button',{name:'Save',exact:true})).toBeVisible();
        expect(await dialog.evaluate(el=>el.scrollWidth<=el.clientWidth)).toBe(true);
        await page.screenshot({path:join(repo,'target/audit-obligation-markdown-narrow.png'),fullPage:true});
      }
      if(mode==='native')await page.screenshot({path:join(repo,'target/audit-obligation-editor.png'),fullPage:true});
      await page.keyboard.insertText('The caller upholds this condition.');
      await dialog.getByRole('button',{name:'Save',exact:true}).click();
      if(!mode.includes('override')){
        await expect(dialog).toHaveAccessibleName('Create override file');
        await page.getByRole('button',{name:'Create & save',exact:true}).click();
      }
      await expect(dialog).not.toBeVisible();
      await expect(page.locator('.draft')).toHaveCount(0);
      await page.reload();await expect(page.locator('.status')).toHaveText('complete · reanalysis needed');
      await page.getByLabel('Finding class',{exact:true}).selectOption('documented-obligation');
      await page.locator('.group').first().click();await page.locator('.finding').first().click();
      await page.getByRole('button',{name:'Justified!',exact:true}).click();
      await expect(context).toBeVisible();
      await expect(prototype).toHaveCount(1);
      await expect(context.getByRole('heading',{name:heading,exact:true,level:4})).toBeVisible();
      await expect(dialog.getByLabel('Override documentation')).toHaveValue(`// ${marker}: The caller upholds this condition.`);
      await dialog.getByRole('button',{name:'Cancel',exact:true}).click();
    } finally { await stop();await rm(dependency,{recursive:true,force:true}); }
  });
}
