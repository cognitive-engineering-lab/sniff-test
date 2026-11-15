import {test,expect} from '@playwright/test';
import {EditorSelection,EditorState,StateEffect,Text} from '@codemirror/state';
import {keymap,type EditorView} from '@codemirror/view';
import {rust} from '@codemirror/lang-rust';
import {history,undo,redo} from '@codemirror/commands';
import {commentEditing,configureCommentEditing,continueRustComments,sourcePromptAttachments} from '../src/source-prompts';

function enter(state:EditorState){
  let next=state;
  const handled=state.facet(keymap).flat().find(binding=>binding.key==='Enter')!.run!({
    state,dispatch:spec=>{next=next.update(spec).state;},
  } as EditorView);
  return {handled,state:next};
}

for(const prefix of ['//','///','//!'])test(`Enter always continues ${prefix} with tab indentation`,()=>{
  let state=EditorState.create({doc:`\t${prefix} λ explanation`,selection:{anchor:`\t${prefix} λ`.length},extensions:[rust(),continueRustComments]});
  let result=enter(state);
  expect(result.handled).toBe(true);
  expect(result.state.doc.toString()).toBe(`\t${prefix} λ\n\t${prefix}  explanation`);
  state=result.state.update({selection:{anchor:result.state.doc.length}}).state;
  result=enter(state);
  expect(result.state.doc.toString()).toBe(`\t${prefix} λ\n\t${prefix}  explanation\n\t${prefix} `);
  result=enter(result.state);
  expect(result.state.doc.toString()).toBe(`\t${prefix} λ\n\t${prefix}  explanation\n\t${prefix} \n\t${prefix} `);
  for(const suffix of ['', ' ']){
    const doc=`    ${prefix}${suffix}`;
    state=EditorState.create({doc,selection:{anchor:4+prefix.length},extensions:[rust(),continueRustComments]});
    expect(enter(state).state.doc.toString()).toBe(`    ${prefix}\n    ${prefix} ${suffix}`);
  }
});

test('Enter leaves raw strings, block comments, code and read-only documents alone',()=>{
  for(const doc of ['const S: &str = r#"\n// text','/*\n/// text','fn target() {','// real comment']){
    const state=EditorState.create({doc,selection:{anchor:doc.length},extensions:[rust(),continueRustComments,EditorState.readOnly.of(doc==='// real comment')]});
    expect(enter(state).handled).toBe(false);
  }
});

test('Enter continues multiple cursors and preserves CRLF serialization',()=>{
  const doc='// first\r\n  /// second';
  const state=EditorState.create({doc,selection:EditorSelection.create([EditorSelection.cursor(8),EditorSelection.cursor(21)]),
    extensions:[rust(),continueRustComments,EditorState.allowMultipleSelections.of(true),EditorState.lineSeparator.of('\r\n')]});
  const result=enter(state);
  expect(result.handled).toBe(true);
  expect(result.state.sliceDoc()).toBe('// first\r\n// \r\n  /// second\r\n  /// ');
});

const documentation={justification:'PANIC',obligation:'# Panics'};
test('inline effect attachment follows layout and only recognizes the configured lexical marker',()=>{
  for(const marker of ['PANIC','SAFETY','ALLOCATION']){
    const source='let read = || bytes[i];';
    const candidate={position:source.indexOf('bytes'),action:'justification',external:false};
    expect(sourcePromptAttachments(source,[candidate],{...documentation,justification:marker})[0]).toMatchObject({insertable:false,attached:false});
    for(const comment of [`// ${marker}: Checked.`, '// Unrelated explanation.', '// OTHER: Checked.', `/// ${marker}: Checked.`, `let text = r#"\n// ${marker}: Checked.\n"#;`]){
      const edited=`let read = ||\n${comment}\n    bytes[i];`;
      const attachment=sourcePromptAttachments(edited,[{...candidate,position:edited.indexOf('bytes')}],{...documentation,justification:marker})[0];
      expect(attachment).toMatchObject({insertable:true,attached:comment===`// ${marker}: Checked.`});
    }
  }
});
function workingComment(){
  const doc='fn target() {\n    // PANIC: explanation\n    risky();\n}\n';
  let state=EditorState.create({doc,selection:{anchor:doc.indexOf('explanation')},extensions:[rust(),commentEditing]});
  state=state.update({effects:configureCommentEditing.of({scope:'finding',documentation,candidates:[{position:doc.indexOf('risky'),action:'justification',external:false}]})}).state;
  expect(state.field(commentEditing).regions).toHaveLength(1);
  return state;
}

test('clearing all documentation removes its empty lines and restores the caret at code',()=>{
  let state=workingComment();
  const line=state.doc.line(2);
  state=state.update({changes:{from:line.from,to:line.to,insert:'\n    '},selection:{anchor:line.from+5},userEvent:'delete'}).state;
  expect(state.doc.toString()).toBe('fn target() {\n    risky();\n}\n');
  expect(state.selection.main.head).toBe(state.doc.toString().indexOf('risky'));
  expect(state.field(commentEditing).regions).toHaveLength(0);
  expect(sourcePromptAttachments(state.doc.toString(),state.field(commentEditing).candidates,documentation)[0].attached).toBe(false);
  const current=state.field(commentEditing);
  state=state.update({effects:configureCommentEditing.of({scope:current.scope,candidates:current.candidates,documentation})}).state;
  expect(state.field(commentEditing).regions).toHaveLength(0);
  state=state.update({selection:{anchor:state.doc.length}}).state;
  expect(state.field(commentEditing).regions).toHaveLength(0);
});

test('clearing only one comment line preserves the editing session',()=>{
  let state=workingComment();
  const at=state.doc.line(2).to;
  state=state.update({changes:{from:at,insert:'\n    // More explanation'},selection:{anchor:at+8}}).state;
  const line=state.doc.line(3);
  state=state.update({changes:{from:line.from,to:line.to,insert:'  '},selection:{anchor:line.from+2}}).state;
  expect(state.field(commentEditing).regions).toHaveLength(1);
  state=state.update({selection:{anchor:state.doc.length}}).state;
  expect(state.field(commentEditing).regions).toHaveLength(0);
});

test('code in the comment region and finding changes end temporary suppression',()=>{
  let state=workingComment();
  const line=state.doc.line(2);
  state=state.update({changes:{from:line.from,to:line.to,insert:'    let x = 1;'},selection:{anchor:line.from+4}}).state;
  expect(state.field(commentEditing).regions).toHaveLength(0);
  state=workingComment();
  state=state.update({effects:configureCommentEditing.of({scope:'other finding',candidates:[],documentation})}).state;
  expect(state.field(commentEditing).regions).toHaveLength(0);
});

test('cleanup preserves surrounding blank lines, attributes, Unicode and CRLF',()=>{
  const doc='// λ\n\n/// # Panics\n/// explanation\n#[allow(dead_code)]\nfn target() {}\n';
  let state=EditorState.create({doc:doc.replaceAll('\n','\r\n'),selection:{anchor:doc.indexOf('explanation')},
    extensions:[rust(),commentEditing,EditorState.lineSeparator.of('\r\n')]});
  state=state.update({effects:configureCommentEditing.of({scope:'finding',documentation,
    candidates:[{position:doc.indexOf('fn target'),action:'obligation',external:false}]})}).state;
  expect(state.field(commentEditing).regions).toHaveLength(1);
  const from=doc.indexOf('///'),to=doc.indexOf('#[allow');
  state=state.update({changes:{from,to:to-1,insert:Text.of(['','  '])},selection:{anchor:from},userEvent:'delete.selection'}).state;
  expect(state.sliceDoc()).toBe('// λ\r\n\r\n#[allow(dead_code)]\r\nfn target() {}\r\n');
  expect(state.selection.main.head).toBe(state.doc.toString().indexOf('#[allow'));
});

test('history and programmatic edits do not trigger comment cleanup',()=>{
  for(const userEvent of ['undo','redo',undefined]){
    let state=workingComment();
    const line=state.doc.line(2);
    state=state.update({changes:{from:line.from,to:line.to},selection:{anchor:line.from},userEvent}).state;
    expect(state.doc.toString()).toBe('fn target() {\n\n    risky();\n}\n');
  }
});

test('cleanup maps multiple selections across separate comment regions',()=>{
  const doc='// PANIC: first\nfn first() {}\n\n// PANIC: second\nfn second() {}\n';
  const first=doc.indexOf('fn first'),second=doc.indexOf('fn second'),secondComment=doc.indexOf('// PANIC: second');
  let state=EditorState.create({doc,selection:EditorSelection.create([EditorSelection.cursor(4),EditorSelection.cursor(secondComment+4)]),
    extensions:[rust(),commentEditing,EditorState.allowMultipleSelections.of(true)]});
  state=state.update({effects:configureCommentEditing.of({scope:'finding',documentation,
    candidates:[first,second].map(position=>({position,action:'justification',external:false}))})}).state;
  state=state.update({changes:[{from:0,to:first-1},{from:secondComment,to:second-1}],userEvent:'delete.selection'}).state;
  expect(state.doc.toString()).toBe('fn first() {}\n\nfn second() {}\n');
  expect(state.selection.ranges.map(r=>r.head)).toEqual([0,'fn first() {}\n\n'.length]);
});

test('immediate cleanup shares one Undo/Redo step with the deletion',()=>{
  let state=workingComment();
  state=state.update({effects:StateEffect.appendConfig.of(history())}).state;
  const before=state.doc.toString(),line=state.doc.line(2);
  state=state.update({changes:{from:line.from,to:line.to},selection:{anchor:line.from},userEvent:'delete.selection'}).state;
  state=state.update({selection:{anchor:state.doc.length},userEvent:'select'}).state;
  const after=state.doc.toString();
  const commandTarget=()=>({state,dispatch:(tr:import('@codemirror/state').Transaction)=>{state=tr.state;}});
  expect(undo(commandTarget())).toBe(true);
  expect(state.doc.toString()).toBe(before);
  expect(redo(commandTarget())).toBe(true);
  expect(state.doc.toString()).toBe(after);
});

test('completed justifications anchor at their marker without swallowing preceding comments',()=>{
  for(const newline of ['\n','\r\n']) {
    const source=['fn f() {','    // Unrelated note λ.','    // SAFETY: A separate effect.','    // PANIC: Expected failure.','    // More detail.','    danger();','}'].join(newline);
    const [attachment]=sourcePromptAttachments(source,[{position:source.indexOf('danger();'),action:'justification',external:false}],{justification:'PANIC',obligation:'# Panics'});
    expect(attachment.attached).toBe(true);
    expect(attachment.markerStart).toBe(source.indexOf('    // PANIC:'));
    expect(attachment.commentStart).toBe(source.indexOf('    // Unrelated'));
  }
});
