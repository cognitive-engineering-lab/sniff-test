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
  await expect(details.locator('.details-scroll > button.link')).toHaveCount(3);
  for(const name of ['Report root','Effect source','Contract'])
    await expect(details.getByRole('button',{name:new RegExp('^'+name)})).toBeVisible();
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
  await page.getByRole('button',{name:'Save draft',exact:true}).click();
  await page.getByRole('button',{name:'Review diff',exact:true}).click();
  await expect(page.locator('.diff')).toContainText('// PANIC: This panic is intentional.');
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

test('call trace highlights the editor location across files and navigation',async({page})=>{
  await stop();
  await writeFile(join(dir,'src/lib.rs'),'\ufeff// λ before the call\r\npub fn entry() {\r\n    helper::danger();\r\n}\r\nmod helper;\r\n');
  await writeFile(join(dir,'src/helper.rs'),'pub fn danger() {\n    panic!("trace location");\n}\n');
  await launch();await selectFinding(page);
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
  await page.getByRole('button',{name:'Review diff',exact:true}).click();
  await expect(page.locator('.trace button[aria-current="location"]')).toHaveCount(0);
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
  await expect(page.getByRole('button',{name:'Save draft',exact:true})).toBeEnabled();
  await clickDanger(true);
  await expect(page.locator('.filename')).toContainText('src/helper.rs');
  await expect(page.locator('.draft')).toHaveCount(1);
  expect(await readFile(join(dir,'src/lib.rs'),'utf8')).not.toContain('draft navigation');
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
    await expect(page.getByRole('button',{name:'Save draft',exact:true})).toBeDisabled();
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
  expect(await readFile(join(dir,'src/lib.rs'),'utf8')).not.toContain('// draft');
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

for(const action of ['Justify via override','Propagate obligations via override']) {
  test(`dependency ${action} saves a virtual diff and confirms existing override edits`,async({page})=>{
    const dependency=await mkdtemp(join(tmpdir(),'sniff-override-dep-'));
    const source='// λ dependency\r\n#[inline]\r\n#[allow(\r\n    unused\r\n)]\r\npub fn danger(flag: bool) {\r\n    #[allow(unused)]\r\n    assert!(flag, "dependency");\r\n}\r\n';
    try {
      await stop();await mkdir(join(dependency,'src'));
      await writeFile(join(dependency,'Cargo.toml'),'[package]\nname="override-dep"\nversion="0.1.0"\nedition="2024"\n');
      await writeFile(join(dependency,'src/lib.rs'),source);
      await writeFile(join(dir,'Cargo.toml'),`[package]\nname="audit-browser-fixture"\nversion="0.1.0"\nedition="2024"\n[workspace]\n[dependencies]\noverride-dep={path=${JSON.stringify(dependency)}}\n`);
      await writeFile(join(dir,'src/lib.rs'),'pub fn entry(flag: bool) { override_dep::danger(flag); }\n');
      await writeFile(join(dir,'sniff-test.toml'),'[contracts]\noverride-files=["existing.toml"]\n');
      await writeFile(join(dir,'existing.toml'),'# Preserve this comment\n[overrides]\n"unrelated::api" = "# Safety\\nExisting contract"\n');
      await launch();await selectFinding(page);
      await expect(page.locator('.buffer-state')).toContainText('Read-only dependency');
      const attribute=page.locator('.cm-line').filter({hasText:action.startsWith('Justify')?'#[allow(unused)]':'#[inline]'});
      async function expectAboveAttribute(label:string){
        const button=await page.getByRole('button',{name:label,exact:true}).boundingBox();
        const line=await attribute.boundingBox();
        expect(button).not.toBeNull();expect(line).not.toBeNull();
        expect(button!.y+button!.height).toBeLessThanOrEqual(line!.y);
      }
      await expectAboveAttribute(action);
      await page.getByRole('button',{name:action,exact:true}).click();
      const dialog=page.getByRole('dialog');
      const template=action.startsWith('Justify')?'// PANIC: ':'/// # Panics\n///\n/// ';
      await expect(dialog.getByLabel('Override documentation')).toHaveValue(template);
      await expect(dialog.getByLabel('Override documentation')).toBeFocused();
      await page.keyboard.insertText('Typed at the end.');
      await expect(dialog.getByLabel('Override documentation')).toHaveValue(template+'Typed at the end.');
      await dialog.getByRole('button',{name:'Cancel',exact:true}).click();
      await expect(page.locator('.draft')).toHaveCount(0);
      await page.getByRole('button',{name:action,exact:true}).click();
      await dialog.getByLabel('Override documentation').fill(template+'The flag is checked by the caller.');
      await dialog.getByRole('button',{name:'Save draft',exact:true}).click();
      await expect(dialog).not.toBeVisible();
      const completed=action.startsWith('Justify')?'Justified!':'Obligation propagated!';
      const alternative=action.startsWith('Justify')?'Propagate obligations via override':'Justify via override';
      await expect(page.getByRole('button',{name:completed,exact:true})).toBeVisible();
      await expectAboveAttribute(completed);
      await expect(page.getByRole('button',{name:alternative,exact:true})).toHaveCount(0);
      await expect(page.locator('.buffer-state button')).toHaveCount(0);
      await page.reload();
      await expect(page.locator('.status')).toHaveText('complete');
      await page.locator('.draft').click();
      await page.getByRole('button',{name:'Source',exact:true}).click();
      await page.getByRole('button',{name:completed,exact:true}).click();
      await expect(dialog.getByLabel('Override documentation')).toHaveValue(template+'The flag is checked by the caller.');
      await dialog.getByRole('button',{name:'Delete draft',exact:true}).click();
      await expect(page.locator('.draft')).toHaveCount(0);
      await expect(page.getByRole('button',{name:action,exact:true})).toBeVisible();
      await expect(page.getByRole('button',{name:alternative,exact:true})).toBeVisible();
      await page.getByRole('button',{name:action,exact:true}).click();
      await dialog.getByLabel('Override documentation').fill(template+'The flag is checked by the caller.');
      await dialog.getByRole('button',{name:'Save draft',exact:true}).click();
      await page.locator('.draft').click();
      await expect(page.locator('main .diff')).toContainText('Override preview');
      await expect(page.locator('main .diff')).toContainText('+');
      await expect(page.locator('main .diff')).toContainText('The flag is checked by the caller.');
      expect((await page.locator('main .diff').innerText()).replaceAll('\r','')).toMatch(/\+[^\n]*The flag is checked by the caller\.\n [ \t]*#\[/);
      expect(await readFile(join(dependency,'src/lib.rs'),'utf8')).toBe(source);
      await page.getByRole('button',{name:'Apply overrides & reanalyze',exact:true}).click();
      await expect(dialog).toHaveAccessibleName('Confirm editing override file');
      await expect(dialog.locator('.diff')).toContainText('overrides.crates');
      await dialog.getByRole('button',{name:'Cancel',exact:true}).click();
      expect(await readFile(join(dir,'existing.toml'),'utf8')).not.toContain('annotations');
      await page.getByRole('button',{name:'Apply overrides & reanalyze',exact:true}).click();
      const applied=page.waitForResponse(r=>r.url().endsWith('/api/v1/override/apply'));
      await dialog.getByRole('button',{name:'Confirm edit & reanalyze',exact:true}).click();
      expect((await applied).ok()).toBe(true);
      await expect(page.locator('.draft')).toHaveCount(0);
      await page.getByRole('button',{name:'Source',exact:true}).click();
      await expect(page.getByRole('button',{name:completed,exact:true})).toBeVisible();
      await expectAboveAttribute(completed);
      await page.getByRole('button',{name:completed,exact:true}).click();
      await expect(dialog.getByRole('button',{name:'Delete draft',exact:true})).toHaveCount(0);
      await dialog.getByLabel('Override documentation').fill(template+'A revised explanation.');
      await dialog.getByRole('button',{name:'Save draft',exact:true}).click();
      await page.getByRole('button',{name:completed,exact:true}).click();
      await dialog.getByRole('button',{name:'Discard changes',exact:true}).click();
      await expect(page.locator('.draft')).toHaveCount(0);
      await page.getByRole('button',{name:completed,exact:true}).click();
      await expect(dialog.getByLabel('Override documentation')).toHaveValue(template+'The flag is checked by the caller.');
      await dialog.getByRole('button',{name:'Cancel',exact:true}).click();
      const file=await readFile(join(dir,'existing.toml'),'utf8');
      expect(file).toContain('# Preserve this comment');expect(file).toContain('unrelated::api');expect(file).toContain('The flag is checked by the caller.');
      expect(await readFile(join(dependency,'src/lib.rs'),'utf8')).toBe(source);
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
  await page.getByRole('button',{name:'Save draft',exact:true}).click();
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
  await expect(page.locator('.draft')).toHaveCount(1);
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
