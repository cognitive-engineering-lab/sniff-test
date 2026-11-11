import React, {useEffect, useLayoutEffect, useRef, useState} from 'react';
import {createRoot} from 'react-dom/client';
import {EditorView, basicSetup} from 'codemirror';
import {EditorState, StateField, Compartment, type ChangeDesc} from '@codemirror/state';
import {Decoration, WidgetType} from '@codemirror/view';
import {rust} from '@codemirror/lang-rust';
import {sourcePromptAttachments, continueRustComments, commentEditing, configureCommentEditing} from './source-prompts';
import './style.css';
import {Navigation, filePath} from './navigation';
import {Autosave, type SaveState} from './autosave';
import {displaySourcePath} from './source-path';
import {ObligationDocumentationPanel, type ObligationDocumentation} from './obligation-documentation';

type Location = {approximate?:boolean;path:string; start:number; end:number; available:boolean; hash?:string; line?:number; live?:boolean};
type Buffer = {path:string; content:string; hash:string; revision:number; writable:boolean; saved_overrides:SavedOverride[]};
type SavedOverride = {annotation:{effect:string; action:string; document:string; obligation_documentation?:ObligationDocumentation; selector:unknown}; location:Location; destination:string};
type Target = {action:string; location:Location; selector?:unknown; overrideIndex?:number};
function sameSelector(a:unknown,b:unknown) {
  if(!a||!b)return false;
  const left=a as Record<string,unknown>,right=b as Record<string,unknown>;
  return ['namespace','crate-name','version','source-path','source-hash','start','end','kind','site'].every(key=>left[key]===right[key]);
}
type OverrideEditor = {token:string; can_remove:boolean; saved_destination:string; document:string; obligation_documentation?:ObligationDocumentation; destination:string; destinations:{path:string;exists:boolean}[]; action:string};
type TemplateEdit = {path:string; revision:number; start:number; end:number; text:string; cursor:number};
type EditorSelection = {path:string; from:number; to:number};
type FindingNavigation = {source?:Location;root?:Location;contract?:Location;trace:(Location|null)[]};
type Finding = {navigation?:FindingNavigation;id:string; crate_name:string; effect?:string;kind:string;class?:string;level:string;root?:string;trace_id?:string;reason:string;requirements:string[];missing_requirements:string[];display_trace:string[]; audit?:{obligation:string; justification:string; source?:Location; root?:Location; contract?:Location; targets:Target[]; trace:{caller:string; target?:string; kind:string; location?:Location}[]}};
type AuditProgress = {justified:boolean;propagated:boolean};
type GroupProgress = {handled:number;total:number;justified:number;propagated:number};
type Summary = {progress?:AuditProgress;id:string; crate_name:string; root:string; reason:string; level:string; effect:string; class:string; path?:string};
type FindingGroup = {progress?:GroupProgress;key:string; label?:string; path?:string; count:number; items?:Summary[]; loading?:boolean; loadError?:string};
type Status = {results_revision?:number;audit_revision?:number;override_revision?:number; override_error?:string; generation:number; running:boolean; stale:boolean; overrides_changed?:boolean; status:string; count:number; log:string};
const token = location.hash.slice(1) || sessionStorage.getItem('audit-token') || '';
if (token) { sessionStorage.setItem('audit-token', token); history.replaceState(null, '', location.pathname); }
async function api(path:string, body?:unknown, signal?:AbortSignal) {
  const response = await fetch('/api/v1/'+path, {signal, method:body === undefined ? 'GET' : 'POST', headers:{'x-audit-token':token, 'Content-Type':'application/json'}, body:body === undefined ? undefined : JSON.stringify(body)});
  if (!response.ok) { const text = await response.text(); let error; try { error = JSON.parse(text).error; } catch {} throw Error(error || `Request failed (${response.status})`); }
  return response.json();
}
class DocumentationPrompt extends WidgetType {
  constructor(readonly action:string, readonly run:()=>void, readonly override=false, readonly added="") { super(); }
  toDOM() {
    const element=document.createElement('div');element.className='inline-prompt';
    const button=document.createElement('button');button.type='button';
    const justify=this.action==='justification';
    const label=this.added?(justify?'Justified!':'Obligation propagated!'):this.override?(justify?'Justify via override':'Propagate obligations via override'):(justify?'Justify here':'Propagate to callers');
    button.textContent=(justify?'✓ ':'↑ ')+label;
    if(this.added)button.classList.add('completed');
    button.setAttribute('aria-label',label);
    button.addEventListener('click',this.run);
    const hint=document.createElement('span');
    hint.textContent=this.added || (justify?"Explain why this is valid":"Document the caller's obligation");
    element.append(button,hint);return element;
  }
  ignoreEvent() { return true; }
}
function bytePosition(text:string, offset:number) { return new TextDecoder('utf-8',{ignoreBOM:true}).decode(new TextEncoder().encode(text).slice(0,offset)).length; }
function editorPosition(text:string, offset:number) { return text.slice(0,bytePosition(text,offset)).replace(/\r\n/g,'\n').length; }
function sourceBytePosition(source:string,position:number) {
  let at=0;
  for(let n=0;n<position&&at<source.length;n++,at++)if(source[at]==='\r'&&source[at+1]==='\n')at++;
  return new TextEncoder().encode(source.slice(0,at)).length;
}
function destination(finding:Finding|undefined,kind:'source'|'root'|'contract') {
  return finding?.navigation?finding.navigation[kind]:finding?.audit?.[kind];
}
function Editor({buffer, locked, reloadKey, onFlush, location:target, onChange, onSelectionChange, finding, enabled, prepare, onOverride, onError, navigation, onReady}:{buffer:Buffer; locked:boolean; reloadKey:number; onFlush:()=>void; location?:Location; onChange:(text:string,changes:ChangeDesc,previous:string)=>void; onSelectionChange:(selection?:EditorSelection)=>void; finding?:Finding; enabled:boolean; prepare:(target:Target)=>Promise<TemplateEdit>; onOverride:(target:Target)=>void; onError:(error:string)=>void; navigation?:Navigation; onReady:(view:EditorView|undefined)=>void}) {
  const documents=useRef(new Map<string,{state:EditorState;content:string;scroll:ReturnType<EditorView['scrollSnapshot']>}>());
  const bufferRef=useRef(buffer);bufferRef.current=buffer;
  const holder = useRef<HTMLDivElement>(null), editorRef=useRef<EditorView | undefined>(undefined);
  const callback = useRef(onChange); callback.current = onChange;
  const selectionRef=useRef(onSelectionChange);selectionRef.current=onSelectionChange;
  const prepareRef=useRef(prepare);prepareRef.current=prepare;
  const overrideRef=useRef(onOverride);overrideRef.current=onOverride;
  const errorRef=useRef(onError);errorRef.current=onError;
  const readyRef=useRef(onReady);readyRef.current=onReady;
  const findingRef=useRef(finding);findingRef.current=finding;
  const flushRef=useRef(onFlush);flushRef.current=onFlush;
  const readOnly=useRef(new Compartment()),promptsConfig=useRef(new Compartment()),navigationConfig=useRef(new Compartment());
  useEffect(()=>{
    if(!holder.current)return;
    const cached=documents.current.get(buffer.path);
    documents.current.delete(buffer.path);
    const state=cached?.content===buffer.content?cached.state.update({effects:[
      readOnly.current.reconfigure(EditorState.readOnly.of(!buffer.writable||locked)),
      navigationConfig.current.reconfigure(navigation?.extension(buffer.path)||[]),
      promptsConfig.current.reconfigure([]),
    ]}).state:EditorState.create({doc:buffer.content,extensions:[
      basicSetup,EditorState.lineSeparator.of(buffer.content.includes('\r\n')?'\r\n':'\n'),rust(),EditorView.lineWrapping,
      continueRustComments,commentEditing,
      readOnly.current.of(EditorState.readOnly.of(!buffer.writable||locked)),promptsConfig.current.of([]),navigationConfig.current.of([]),
      EditorView.domEventHandlers({blur:()=>{flushRef.current();},keydown:event=>{
        if((event.metaKey||event.ctrlKey)&&event.key.toLowerCase()==='s'){event.preventDefault();flushRef.current();return true;}
        return false;
      }}),
      EditorView.updateListener.of(update=>{
        if(update.docChanged)callback.current(update.state.sliceDoc(),update.changes,update.startState.sliceDoc());
        if(update.selectionSet||update.docChanged){const {from,to}=update.state.selection.main;selectionRef.current({path:bufferRef.current.path,from,to});}
      }),
    ]});
    const view=new EditorView({parent:holder.current,state});
    if(cached?.content===buffer.content)view.dispatch({effects:cached.scroll});
    editorRef.current=view;readyRef.current(view);
    return()=>{
      documents.current.set(buffer.path,{state:view.state,content:view.state.sliceDoc(),scroll:view.scrollSnapshot()});
      if(documents.current.size>8)documents.current.delete(documents.current.keys().next().value!);
      readyRef.current(undefined);selectionRef.current(undefined);editorRef.current=undefined;view.destroy();
    };
  },[buffer.path,reloadKey]);
  useEffect(()=>{editorRef.current?.dispatch({effects:readOnly.current.reconfigure(EditorState.readOnly.of(!buffer.writable||locked))});},[buffer.writable,locked,buffer.path,reloadKey]);
  useEffect(()=>{editorRef.current?.dispatch({effects:navigationConfig.current.reconfigure(navigation?.extension(buffer.path)||[])});},[navigation,buffer.path,reloadKey]);
  useEffect(()=>{
    const view=editorRef.current;if(!view)return;
    if(enabled&&view.state.sliceDoc()!==buffer.content)return;
    const overrides=buffer.saved_overrides;
    const targets=finding?.audit?.targets || [];
    const resolved=targets.some(t=>overrides.some(a=>a.annotation.effect===finding?.effect && a.annotation.action===t.action && sameSelector(a.annotation.selector,t.selector)));
    const pendingTargets=targets.filter(t=>!t.selector || !resolved);
    const completedTargets:Target[]=overrides.map((a,overrideIndex)=>({action:a.annotation.action,location:a.location,selector:a.annotation.selector,overrideIndex}));
    const candidates=[...pendingTargets,...completedTargets].filter(t=>(buffer.writable || t.selector) && t.location.path===buffer.path && t.location.available && t.location.hash===buffer.hash).map(t=>{
      const position=editorPosition(buffer.content,t.location.start);
      const added=t.overrideIndex===undefined?undefined:overrides[t.overrideIndex];
      const widget=new DocumentationPrompt(t.action,()=>{
        if(t.selector){overrideRef.current(t);return;}
        const snapshot=view.state.sliceDoc();
        prepareRef.current(t).then(edit=>{
          if(editorRef.current!==view||findingRef.current?.id!==finding?.id)return;
          if(view.state.readOnly || view.state.sliceDoc()!==snapshot || edit.path!==buffer.path)throw Error('Source changed while preparing the template. Reanalyze before retrying.');
          const from=bytePosition(snapshot,edit.start),to=bytePosition(snapshot,edit.end);
          const updated=snapshot.slice(0,from)+edit.text+snapshot.slice(to);
          const cursor=editorPosition(updated,edit.cursor);
          view.dispatch({changes:edit.text?{from:editorPosition(snapshot,edit.start),to:editorPosition(snapshot,edit.end),insert:edit.text}:undefined,selection:{anchor:cursor},effects:EditorView.scrollIntoView(cursor,{y:'center'}),userEvent:'input'});
          view.focus();
        }).catch(e=>{if(editorRef.current===view)errorRef.current(String(e));});
      },!!t.selector,added?'Override saved':'');
      return {position,action:t.action,external:!!t.selector,widget};
    });
    type Candidate = typeof candidates[number];
    function decorate(state:EditorState, candidates:Candidate[]) {
      if(!enabled)return Decoration.none;
      const attachments=sourcePromptAttachments(state.doc.toString(),candidates,finding?.audit);
      const resolved=attachments.some(a=>a.attached)||state.field(commentEditing).regions.length>0;
      return Decoration.set(candidates.flatMap((candidate,index)=>{
        const attachment=attachments[index];
        if(!candidate.external && (resolved || !attachment.ownLine))return [];
        return [Decoration.widget({widget:candidate.widget,block:true,side:-1}).range(attachment.lineStart)];
      }),true);
    }
    // Keep hidden candidates too: undo/deletion must be able to restore them.
    const prompts=StateField.define({
      create:(state)=>({candidates,decorations:decorate(state,candidates)}),
      update:(value,tr)=>{
        if(!tr.docChanged&&!tr.selection&&!tr.effects.some(e=>e.is(configureCommentEditing)))return value;
        const candidates=value.candidates.map(candidate=>({...candidate,position:tr.changes.mapPos(candidate.position,1)}));
        return {candidates,decorations:decorate(tr.state,candidates)};
      },
      provide:field=>EditorView.decorations.from(field,value=>value.decorations),
    });
    view.dispatch({effects:[configureCommentEditing.of({scope:`${finding?.id}:${enabled}`,candidates:enabled?candidates:[],documentation:finding?.audit}),promptsConfig.current.reconfigure(prompts)]});
  },[buffer.path,buffer.revision,finding?.id,finding?.audit?.targets,enabled,reloadKey]);
  useEffect(()=>{
    const view=editorRef.current;
    if(!view || !target?.available || target.path!==buffer.path)return;
    const source=view.state.sliceDoc();
    const from=editorPosition(source,target.start),to=editorPosition(source,target.end);
    if(from<=to && to<=view.state.doc.length){view.dispatch({selection:{anchor:from,head:to},effects:EditorView.scrollIntoView(from,{y:'center'})});view.focus();}
  },[target,buffer.path,reloadKey]);
  return <div className="editor" ref={holder} aria-label="Rust source editor"/>;
}
function placeCaretAtEnd(element:HTMLTextAreaElement|null) {
  if(element)element.setSelectionRange(element.value.length,element.value.length);
}
function OverridePanel({title,children,onClose,step}:{title:string;children:React.ReactNode;onClose:()=>void;step:string}) {
  const ref=useRef<HTMLDialogElement>(null);
  const drag=useRef<{x:number;y:number;left:number;top:number}|undefined>(undefined);
  const position=useRef<{left:number;top:number}|undefined>(undefined);
  function place(left:number,top:number) {
    const panel=ref.current;
    if(!panel)return;
    const bounds=panel.getBoundingClientRect();
    position.current={left:Math.max(16,Math.min(left,window.innerWidth-bounds.width-16)),top:Math.max(16,Math.min(top,window.innerHeight-bounds.height-16))};
    panel.style.left=`${position.current.left}px`;panel.style.top=`${position.current.top}px`;
  }
  useLayoutEffect(()=>{
    const panel=ref.current!;
    panel.show();
    const bounds=panel.getBoundingClientRect();
    place(window.innerWidth*.62-bounds.width/2,(window.innerHeight-bounds.height)/2);
    const clamp=()=>{if(position.current)place(position.current.left,position.current.top);};
    const observer=new ResizeObserver(clamp);observer.observe(panel);
    window.addEventListener('resize',clamp);
    return()=>{observer.disconnect();window.removeEventListener('resize',clamp);panel.close();};
  },[]);
  useEffect(()=>{ref.current?.querySelector<HTMLTextAreaElement|HTMLInputElement>('textarea,input')?.focus();},[step]);
  return <dialog ref={ref} className="override-panel" aria-label={title} onKeyDown={e=>{if(e.key==='Escape'&&!e.defaultPrevented){e.preventDefault();onClose();}}}>
    <div className="override-titlebar">
      <div className="override-drag-handle" role="button" tabIndex={0} aria-label="Move override popup" title="Drag to move; use arrow keys when focused"
        onPointerDown={e=>{if(e.button!==0)return;e.preventDefault();e.currentTarget.focus();e.currentTarget.setPointerCapture(e.pointerId);const bounds=ref.current!.getBoundingClientRect();drag.current={x:e.clientX,y:e.clientY,left:bounds.left,top:bounds.top};}}
        onPointerMove={e=>{if(drag.current)place(drag.current.left+e.clientX-drag.current.x,drag.current.top+e.clientY-drag.current.y);}}
        onPointerUp={e=>{drag.current=undefined;e.currentTarget.releasePointerCapture(e.pointerId);}}
        onPointerCancel={()=>{drag.current=undefined;}} onLostPointerCapture={()=>{drag.current=undefined;}}
        onKeyDown={e=>{const dx=e.key==='ArrowLeft'?-20:e.key==='ArrowRight'?20:0,dy=e.key==='ArrowUp'?-20:e.key==='ArrowDown'?20:0;if((dx||dy)&&position.current){e.preventDefault();place(position.current.left+dx,position.current.top+dy);}}}
      ><h2>{title}</h2><span aria-hidden="true">⠿</span></div>
      <button type="button" aria-label="Close override popup" onClick={onClose}>×</button>
    </div>
    <div className="override-panel-content">{children}</div>
  </dialog>;
}
function PanelDivider({side,size,onResize}:{side:'left'|'right';size:number;onResize:(size:number)=>void}) {
  const [stacked,setStacked]=useState(()=>matchMedia('(max-width:1050px)').matches);
  const drag=useRef<{start:number;size:number}|undefined>(undefined);
  useEffect(()=>{const media=matchMedia('(max-width:1050px)');const update=()=>setStacked(media.matches);media.addEventListener('change',update);return()=>media.removeEventListener('change',update);},[]);
  const horizontal=side==='right'&&stacked;
  const resize=(value:number)=>onResize(Math.max(120,Math.min(600,value)));
  return <div className={'panel-divider '+side} role="separator" tabIndex={0} aria-label={side==='left'?'Resize findings panel':'Resize details panel'} aria-orientation={horizontal?'horizontal':'vertical'} aria-valuemin={120} aria-valuemax={600} aria-valuenow={size}
    onPointerDown={e=>{if(e.button!==0)return;e.preventDefault();e.currentTarget.focus();e.currentTarget.setPointerCapture(e.pointerId);drag.current={start:horizontal?e.clientY:e.clientX,size};}}
    onPointerMove={e=>{if(drag.current)resize(drag.current.size+((horizontal?e.clientY:e.clientX)-drag.current.start)*(side==='left'?1:-1));}}
    onPointerUp={e=>{drag.current=undefined;e.currentTarget.releasePointerCapture(e.pointerId);}} onLostPointerCapture={()=>{drag.current=undefined;}} onPointerCancel={()=>{drag.current=undefined;}}
    onKeyDown={e=>{const delta=horizontal?(e.key==='ArrowUp'?20:e.key==='ArrowDown'?-20:0):(e.key==='ArrowRight'?20:e.key==='ArrowLeft'?-20:0)*(side==='left'?1:-1);if(delta||e.key==='Home'||e.key==='End'){e.preventDefault();resize(e.key==='Home'?120:e.key==='End'?600:size+delta);}}}/>;
}
function AuditMarks({progress,group=false}:{progress?:AuditProgress|GroupProgress;group?:boolean}) {
  if(!progress || (!progress.justified&&!progress.propagated))return null;
  const aggregate=group?progress as GroupProgress:undefined;
  if(aggregate && aggregate.handled<aggregate.total){
    return aggregate.handled>0?<span className="audit-progress partial" aria-label={`${aggregate.handled} of ${aggregate.total} matching traces handled`} title={`${aggregate.handled} of ${aggregate.total} matching traces have saved explanations; reanalyze to verify`}>{aggregate.handled}/{aggregate.total}</span>:null;
  }
  return <span className="audit-progress">
    {!!progress.justified&&<span role="img" aria-label="Justification saved" title="Justification saved; reanalyze to verify">✓</span>}
    {!!progress.propagated&&<span role="img" aria-label="Propagation saved" title="Propagation documentation saved; reanalyze to verify">↑</span>}
  </span>;
}

function App() {
  const [leftWidth,setLeftWidth]=useState(285),[rightWidth,setRightWidth]=useState(315);
  const [root,setRoot]=useState(''); const [status,setStatus]=useState<Status>({generation:0,running:false,stale:true,status:'connecting',count:0,log:''});
  const [groups,setGroups]=useState<FindingGroup[]>([]),[total,setTotal]=useState(0),[totalGroups,setTotalGroups]=useState(0),[effects,setEffects]=useState<string[]>([]);
  const [inverted,setInverted]=useState(false);
  const [expanded,setExpanded]=useState<Set<string>>(()=>new Set());
  const [sourceExpanded,setSourceExpanded]=useState<Set<string>>(()=>new Set());
  const [query,setQuery]=useState(''),[effect,setEffect]=useState(''),[level,setLevel]=useState(''),[kind,setKind]=useState('');
  const [pages,setPages]=useState([0,0]);
  const page=pages[Number(inverted)];
  function setPage(value:number|((page:number)=>number)){listScroll.current[Number(inverted)]=0;setPages(previous=>previous.map((p,i)=>i===Number(inverted)?typeof value==='function'?value(p):value:p));}
  function resetPages(){setPages([0,0]);listScroll.current=[0,0];}
  const listElement=useRef<HTMLDivElement>(null),listScroll=useRef([0,0]);
  const listCache=useRef(new Map<string,{groups:FindingGroup[];total:number;total_groups:number;effects:string[]}>());
  const rowCache=useRef(new Map<string,Summary[]>());
  const rowReads=useRef(new Map<string,AbortController>());
  const [listLoading,setListLoading]=useState(false),[listFailure,setListFailure]=useState(''),[listRetry,setListRetry]=useState(0);
  const [listResult,setListResult]=useState('');
  const listRevision=JSON.stringify([status.results_revision,status.generation,status.running,status.audit_revision,status.override_revision]);
  const listFilter=JSON.stringify([query,effect,level,kind,inverted]);
  const listKey=JSON.stringify([listRevision,listFilter,page]);
  const activeList=useRef(listKey);activeList.current=listKey;
  const filters=()=>({q:query,effect,level,class:kind,grouped:'true',group_by:inverted?'effect-source':'file'});
  function cacheRows(key:string,rows:Summary[]){rowCache.current.delete(key);rowCache.current.set(key,rows);if(rowCache.current.size>32)rowCache.current.delete(rowCache.current.keys().next().value!);}
  function rowsKey(key:string){return JSON.stringify([listRevision,listFilter,key]);}
  const [selected,setSelected]=useState<Finding>(),[buffer,setBuffer]=useState<Buffer>(),[text,setText]=useState(''),[target,setTarget]=useState<Location>();
  const [saveState,setSaveState]=useState<SaveState>({status:'saved'}),[reloadKey,setReloadKey]=useState(0),[startingAnalysis,setStartingAnalysis]=useState(false),[opening,setOpening]=useState(false);
  const [error,setError]=useState(''),[busy,setBusy]=useState(false),[logs,setLogs]=useState(false);
  const [nav,setNav]=useState<Location[]>([]);
  const [overrideEditor,setOverrideEditor]=useState<OverrideEditor>();
  const [confirmRemoval,setConfirmRemoval]=useState(false);
  const [createFile,setCreateFile]=useState(false),[overrideFilename,setOverrideFilename]=useState('sniff-test-overrides.toml');
  const [savedOverride,setSavedOverride]=useState('');
  const [editorSelection,setEditorSelection]=useState<EditorSelection>();
  const [navigation,setNavigation]=useState<Navigation>(),[navigationStatus,setNavigationStatus]=useState('');
  function acceptStatus(next:Status){setStatus(previous=>{
    if((next.results_revision??0)<(previous.results_revision??0) || (next.audit_revision??0)<(previous.audit_revision??0) || next.generation<previous.generation || (next.override_revision??0)<(previous.override_revision??0))return previous;
    if(next.generation===previous.generation&&!previous.running&&!next.running)return {...next,stale:previous.stale||next.stale,overrides_changed:previous.overrides_changed||next.overrides_changed};
    return next;
  });}
  const selectedRef=useRef(selected);selectedRef.current=selected;
  const saver=useRef<Autosave<Buffer>|undefined>(undefined);
  if(!saver.current)saver.current=new Autosave<Buffer>(async(snapshot,content)=>{
    const finding=selectedRef.current?.id;
    const result=await api('source/save',{path:snapshot.path,revision:snapshot.revision,content,finding});
    acceptStatus(result.status);
    if(result.finding===finding&&result.targets)setSelected(current=>current&&current.id===finding&&current.audit?{...current,navigation:result.navigation,audit:{...current.audit,targets:result.targets}}:current);
    return result.buffer;
  },setBuffer,setSaveState);
  const openSequence=useRef(0),navigationRead=useRef<AbortController|undefined>(undefined);
  function startNavigation(){navigationRead.current?.abort();navigationRead.current=new AbortController();setOpening(true);return ++openSequence.current;}
  const activeWork=useRef(0);
  function changeSource(content:string,changes:ChangeDesc,previous:string){
    const path=saver.current!.snapshot?.path;
    setNav(history=>history.map(loc=>{
      if(loc.path!==path || !loc.live)return loc;
      const from=changes.mapPos(editorPosition(previous,loc.start),1);
      const to=Math.max(from,changes.mapPos(editorPosition(previous,loc.end),-1));
      return {...loc,start:sourceBytePosition(content,from),end:sourceBytePosition(content,to)};
    }));
    setText(content);saver.current!.change(content);
  }
  function flushSource(){void saver.current!.flush().catch(()=>{});}
  async function reanalyze(){
    setStartingAnalysis(true);
    try{await saver.current!.flush();const result=await api('analysis',{});acceptStatus(result.status);}
    finally{setStartingAnalysis(false);}
  }
  async function reloadSource(){
    if(!buffer)return;
    setOpening(true);
    try {
      const next=await api('buffer?'+new URLSearchParams({path:buffer.path}));
      saver.current!.load(next,true);setBuffer(next);setText(next.content);setTarget(undefined);setReloadKey(key=>key+1);
      navigation?.document(next.path,next.content);
    } finally {setOpening(false);}
  }
  useEffect(()=>{
    const flush=()=>{flushSource();};window.addEventListener('blur',flush);
    return()=>{window.removeEventListener('blur',flush);saver.current?.dispose();};
  },[]);
  useEffect(()=>{
    if(!buffer || buffer.writable)return;
    let cancelled=false;
    const path=buffer.path;
    api('buffer?'+new URLSearchParams({path})).then((next:Buffer)=>{
      if(cancelled)return;
      // Refresh metadata only; never replace editor content or pending source edits.
      setBuffer(current=>current?.path===path && current.hash===next.hash
        ?{...current,saved_overrides:next.saved_overrides,revision:next.revision}:current);
    }).catch(e=>{if(!cancelled)setError(String(e));});
    return()=>{cancelled=true;};
  },[status.override_revision,buffer?.path]);
  const editor=useRef<EditorView|undefined>(undefined);
  const waitingEditor=useRef<{path:string;resolve:(view:EditorView|null)=>void}|undefined>(undefined);
  function editorReady(view:EditorView|undefined){editor.current=view;if(view && waitingEditor.current && waitingEditor.current.path===buffer?.path){waitingEditor.current.resolve(view);waitingEditor.current=undefined;}}
  const rememberDefinition=useRef<(view:EditorView)=>void>(()=>{});
  rememberDefinition.current=view=>rememberPosition(view);
  const displayDefinition=useRef<(uri:string)=>Promise<EditorView|null>>(async()=>null);
  displayDefinition.current=async(uri)=>{
    await saver.current!.flush();
    const path=filePath(uri);
    if(buffer?.path===path)return editor.current || null;
    waitingEditor.current?.resolve(null);
    const ready=new Promise<EditorView|null>(resolve=>{waitingEditor.current={path,resolve};});
    try{await open({path,start:0,end:0,available:false},false);}catch(e){setError(String(e));waitingEditor.current?.resolve(null);waitingEditor.current=undefined;}
    return ready;
  };
  useEffect(()=>{
    if(!root)return;
    const service=new Navigation(token,root,uri=>displayDefinition.current(uri),setNavigationStatus,view=>rememberDefinition.current(view));
    setNavigation(service);void service.start();
    return ()=>{service.stop();waitingEditor.current?.resolve(null);};
  },[root]);
  useEffect(()=>{
    if(!navigation || status.running)return;
    let cancelled=false;
    // Refresh closed language-server documents from disk after analysis.
    for(const file of navigation.client.workspace.files){
      if(file.getView())continue;
      const path=filePath(file.uri);
      api('buffer?'+new URLSearchParams({path})).then((next:Buffer)=>{if(!cancelled)navigation.document(next.path,next.content);}).catch(()=>{});
    }
    return ()=>{cancelled=true;};
  },[navigation,status.generation,status.running]);
  const detailsScroll = useRef<HTMLDivElement>(null);
  useLayoutEffect(()=>{detailsScroll.current?.scrollTo({top:0});},[selected?.id,inverted]);
  const unsaved = !!buffer && text !== buffer.content;
  async function act(work:()=>Promise<unknown>) {activeWork.current++;setBusy(true);setError('');try{await work();}catch(e){setError(String(e));}finally{if(--activeWork.current===0)setBusy(false);}}

  function rememberPosition(view:EditorView|undefined){
    if(!buffer || !view)return;
    const state=view.state,selection=state.selection.main;
    setNav(n=>[...n,{path:buffer.path,start:new TextEncoder().encode(state.sliceDoc(0,selection.from)).length,end:new TextEncoder().encode(state.sliceDoc(0,selection.to)).length,available:true,live:true}]);
  }
  async function open(loc:Location, remember=true, sequence=startNavigation()){
    try {
    await saver.current!.flush();
    if(sequence!==openSequence.current)return false;
    if(remember)rememberPosition(editor.current);
    const current=saver.current!.snapshot;
    let sameFile=current?.path===loc.path&&!!editor.current;
    if(sameFile&&loc.hash&&current!.hash!==loc.hash)sameFile=false;
    if(!sameFile)setOpening(true);
    const next:Buffer=sameFile?current!:await api('buffer?'+new URLSearchParams({path:loc.path}),undefined,navigationRead.current?.signal);if(sequence!==openSequence.current)return false;let destination=loc;
    if(loc.available && loc.hash){
      if(next.hash!==loc.hash){destination={...loc,available:false};setError('Source changed since analysis. Reanalyze to restore precise navigation.');}
    }
    if(!loc.available && loc.hash)setError('The recorded source range could not be verified. Reanalyze or restore the original source.');
    if(waitingEditor.current?.path===loc.path){
      waitingEditor.current.path=next.path;
      if(buffer && buffer.path===next.path && editor.current && buffer.revision===next.revision){waitingEditor.current.resolve(editor.current);waitingEditor.current=undefined;}
    }
    if(!sameFile){
      await saver.current!.flush();if(sequence!==openSequence.current)return false;
      saver.current!.load(next);setBuffer(next);setText(next.content);
      if(current?.path===next.path&&current.content!==next.content)setReloadKey(key=>key+1);
    }
    setTarget({...destination,path:next.path});return true;
    } catch(e){if(sequence===openSequence.current)throw e;return false;}
    finally {if(sequence===openSequence.current)setOpening(false);}
  }
  async function choose(item:Summary){
    const sequence=startNavigation();
    try {
      await saver.current!.flush();if(sequence!==openSequence.current)return;
      const finding:Finding=await api('finding?'+new URLSearchParams({id:item.id}),undefined,navigationRead.current?.signal);
      if(sequence!==openSequence.current)return;
      const location=[destination(finding,'source'),destination(finding,'root')].find(value=>value?.available);
      if(!location||await open(location,true,sequence))setSelected(finding);
    }catch(e){if(sequence===openSequence.current)throw e;}
    finally{if(sequence===openSequence.current)setOpening(false);}
  }
  async function navigateFinding(kind:'source'|'root'|'contract'|number) {
    const id=selectedRef.current?.id;
    if(!id)return;
    const sequence=startNavigation();
    try {
      await saver.current!.flush();if(sequence!==openSequence.current)return;
      const finding:Finding=await api('finding?'+new URLSearchParams({id}),undefined,navigationRead.current?.signal);
      if(sequence!==openSequence.current||selectedRef.current?.id!==id)return;
      const loc=typeof kind==='number'
        ?(finding.navigation?finding.navigation.trace[kind]:finding.audit?.trace[kind]?.location)
        :destination(finding,kind);
      if(!loc||await open(loc,true,sequence))setSelected(finding);
    }catch(e){if(sequence===openSequence.current)throw e;}
    finally{if(sequence===openSequence.current)setOpening(false);}
  }
  useEffect(()=>{api('workspace').then(v=>setRoot(v.root)).catch(e=>setError(String(e)));
    const controller=new AbortController();
    (async()=>{try{
      const response=await fetch('/api/v1/events',{headers:{'x-audit-token':token},signal:controller.signal});
      if(!response.ok)throw Error('Cannot connect. Open the full URL printed by cargo sniff-test.');
      const reader=response.body!.getReader(),decoder=new TextDecoder();let pending='';
      while(true){const {done,value}=await reader.read();if(done)break;pending+=decoder.decode(value,{stream:true});let boundary;
        while((boundary=pending.indexOf('\n\n'))>=0){const event=pending.slice(0,boundary);pending=pending.slice(boundary+2);const data=event.split('\n').find(l=>l.startsWith('data:'));if(data)acceptStatus(JSON.parse(data.slice(5)));}}
    }catch(e){if(!controller.signal.aborted)setError(String(e));}})();return()=>controller.abort();
  },[]);
  useEffect(()=>{
    const controller=new AbortController();
    setListFailure('');
    const cached=listCache.current.get(listKey);
    function display(value:{groups:FindingGroup[];total:number;total_groups:number;effects:string[]}){
      if(activeList.current!==listKey)return;
      const lastPage=Math.max(0,Math.ceil(value.total_groups/100)-1);
      if(page>lastPage){setPage(lastPage);return;}
      setGroups(value.groups.map(group=>({...group,items:rowCache.current.get(rowsKey(group.key))||group.items})));
      setTotal(value.total);setTotalGroups(value.total_groups);setEffects(value.effects);setListResult(listKey);setListLoading(false);
    }
    if(cached){display(cached);return;}
    setListLoading(true);
    api('findings?'+new URLSearchParams({...filters(),headers_only:'true',offset:String(page*100)}),undefined,controller.signal).then(value=>{
      if(controller.signal.aborted)return;
      listCache.current.set(listKey,value);
      if(listCache.current.size>16)listCache.current.delete(listCache.current.keys().next().value!);
      display(value);
    }).catch(e=>{if(!controller.signal.aborted&&activeList.current===listKey){setGroups([]);setTotal(0);setTotalGroups(0);setListResult(listKey);setListFailure(String(e));setListLoading(false);}});
    return ()=>controller.abort();
  },[listKey,listRetry]);
  useLayoutEffect(()=>{
    if(listResult===listKey&&listElement.current)listElement.current.scrollTop=listScroll.current[Number(inverted)];
  },[listKey,listResult,groups]);
  useEffect(()=>()=>{for(const controller of rowReads.current.values())controller.abort();rowReads.current.clear();},[listKey]);
  async function loadRows(key:string,more=false){
    const requestKey=listKey,cacheKey=rowsKey(key);
    const current=groups.find(g=>g.key===key);
    if(!current||current.loading||rowReads.current.has(key))return;
    const controller=new AbortController();rowReads.current.set(key,controller);
    const existing=more?(current.items||[]):[];
    setGroups(previous=>previous.map(g=>g.key===key?{...g,loading:true,loadError:undefined}:g));
    try{
      const value=await api('group-items?'+new URLSearchParams({...filters(),group_key:key,offset:String(existing.length),limit:'100'}),undefined,controller.signal);
      if(activeList.current!==requestKey)return;
      const items=[...existing,...value.items];cacheRows(cacheKey,items);
      setGroups(previous=>previous.map(g=>g.key===key?{...g,items,loading:false}:g));
    }catch(e){if(!controller.signal.aborted&&activeList.current===requestKey)setGroups(previous=>previous.map(g=>g.key===key?{...g,loading:false,loadError:String(e)}:g));}
    finally{if(rowReads.current.get(key)===controller)rowReads.current.delete(key);}
  }
  useEffect(()=>{
    if(listResult!==listKey)return;
    const open=inverted?sourceExpanded:expanded;
    for(const group of groups)if(open.has(group.key)&&!group.items&&!group.loading&&!group.loadError)void loadRows(group.key);
  },[groups,expanded,sourceExpanded,listResult,listKey]);
  useEffect(()=>{openSequence.current++;navigationRead.current?.abort();setOpening(false);setSelected(undefined);setSavedOverride('');},[status.generation,status.results_revision]);
  useEffect(()=>{const warn=(e:BeforeUnloadEvent)=>{if(saver.current?.pending||overrideEditor){e.preventDefault();}};window.addEventListener('beforeunload',warn);return()=>window.removeEventListener('beforeunload',warn)},[unsaved,overrideEditor]);
  async function openOverride(t:Target) {
    if(overrideEditor){document.querySelector<HTMLElement>('.override-drag-handle')?.focus();return;}
    if(!buffer)return;
    const annotation=t.overrideIndex===undefined?undefined:buffer.saved_overrides[t.overrideIndex];
    if(!annotation&&!selected)throw Error('Select a finding before adding an override.');
    const request=annotation?{path:buffer.path,index:t.overrideIndex,revision:buffer.revision}:{id:selected?.id,action:t.action,revision:buffer.revision,generation:status.generation};
    const context=await api('override/editor',request);
    setCreateFile(false);setOverrideFilename('sniff-test-overrides.toml');
    setConfirmRemoval(false);
    setOverrideEditor({...context,saved_destination:context.destination,action:t.action});
  }
  async function commitOverride(filename?:string) {
    if(!overrideEditor)return;
    const result=await api('override/commit',{token:overrideEditor.token,destination:overrideEditor.destination,document:overrideEditor.document,filename});
    saver.current!.load(result.buffer);setBuffer(result.buffer);setText(result.buffer.content);acceptStatus(result.status);
    setSavedOverride(result.destination);setCreateFile(false);setOverrideEditor(undefined);
  }

  async function removeOverride() {
    if(!overrideEditor)return;
    const result=await api('override/remove',{token:overrideEditor.token});
    saver.current!.load(result.buffer);setBuffer(result.buffer);setText(result.buffer.content);acceptStatus(result.status);
    setSavedOverride('');setConfirmRemoval(false);setOverrideEditor(undefined);
  }

  const trace=(selected?.audit?.trace||[]).map((step,i)=>({...step,location:selected?.navigation?selected.navigation.trace[i]??undefined:step.location}));
  const traceEntries=trace.map((step,i)=>({step,i}));
  if(inverted)traceEntries.reverse();
  const activeTraceIndex=buffer && !unsaved && editorSelection?.path===buffer.path
    ? trace.findIndex(step=>{
      const loc=step.location;
      if(!loc?.available || loc.path!==buffer.path)return false;
      const from=editorPosition(buffer.content,loc.start),to=editorPosition(buffer.content,loc.end);
      return editorSelection.from===from && editorSelection.to===to;
    }) : -1;
  const activeTraceCaretIndex=activeTraceIndex<0 && buffer && !unsaved && editorSelection?.path===buffer.path && editorSelection.from===editorSelection.to
    ? trace.findIndex(step=>{
      const loc=step.location;
      if(!loc?.available || loc.path!==buffer.path)return false;
      const from=editorPosition(buffer.content,loc.start),to=editorPosition(buffer.content,loc.end);
      return from<=editorSelection.from && editorSelection.from<(to===from?to+1:to);
    }) : -1;
  const highlightedTraceIndex=activeTraceIndex>=0?activeTraceIndex:activeTraceCaretIndex;
  return <div className="app">
    <header><div className="brand"><b>sniff-test</b><span> / audit</span></div><span className="workspace" title={root}>{root}</span><span className={'status '+status.status}>{status.status}{status.stale?' · stale':status.overrides_changed?' · reanalysis needed':''}</span><button disabled={status.running||startingAnalysis||busy} onClick={()=>act(reanalyze)}>↻ Reanalyze</button></header>
    {error&&<div className="error" role="alert">{error}<button onClick={()=>setError('')}>Dismiss</button></div>}
    <div className="layout" style={{'--left-size':`${leftWidth}px`,'--right-size':`${rightWidth}px`} as React.CSSProperties}><div className="side-pane left-pane" id="findings-panel"><aside className="findings"><div className="section-title">FINDINGS <span>{total}</span></div>
      <button type="button" className="invert-effect" aria-pressed={inverted} onClick={()=>{if(listElement.current)listScroll.current[Number(inverted)]=listElement.current.scrollTop;setInverted(value=>!value);}}>⇄ Invert effect</button>
      <input aria-label={inverted?'Search effect sources':'Search findings'} placeholder={inverted?'Search effect sources…':'Search files, roots, crates…'} value={query} onChange={e=>{setQuery(e.target.value);resetPages();}}/>
      <div className="filters"><select aria-label="Effect" value={effect} onChange={e=>{setEffect(e.target.value);resetPages();}}><option value="">All effects</option>{effects.map(e=><option key={e}>{e}</option>)}</select><select aria-label="Severity" value={level} onChange={e=>{setLevel(e.target.value);resetPages();}}><option value="">All levels</option><option>warn</option><option>deny</option></select></div>
      <select aria-label="Finding class" value={kind} onChange={e=>{setKind(e.target.value);resetPages();}}><option value="">All finding classes</option>{['concrete-operation','concrete-invocation','documented-obligation','undocumented-invocation','unresolved-call-target','analysis-incomplete','ambiguous-marker','ambiguous-requirement'].map(k=><option key={k}>{k}</option>)}</select>
      <div className="finding-list" ref={listElement} aria-busy={listLoading||listResult!==listKey} onScroll={e=>{if(listResult===listKey)listScroll.current[Number(inverted)]=e.currentTarget.scrollTop;}}>{(listLoading||listResult!==listKey)&&<div className="loading" role="status">Loading {inverted?'effect sources':'files'}…</div>}{(listResult===listKey?groups:[]).map(({key, label,path:sourcePath,items:rows,count,progress,loading,loadError},index)=>{
        const path=label||key;
        const isOpen=(inverted?sourceExpanded:expanded).has(key),listId=`${inverted?'source':'file'}-findings-${index}`;
        return <section key={key}><button type="button" className="group" title={path} aria-expanded={isOpen} aria-controls={listId} onClick={()=>(inverted?setSourceExpanded:setExpanded)(previous=>{const next=new Set(previous);if(next.has(key))next.delete(key);else next.add(key);return next;})}><span className="group-chevron" aria-hidden="true">{isOpen?'▾':'▸'}</span><span className="group-path">{sourcePath?path.replace(sourcePath,()=>displaySourcePath(sourcePath,root)):displaySourcePath(path,root)}</span><AuditMarks progress={progress} group/><span className="group-count" aria-label={`${count} ${inverted?'reports':'effects'}`} >{count}</span></button><div id={listId} hidden={!isOpen}>{isOpen&&(rows||[]).map(item=><button className={'finding '+(selected?.id===item.id?'selected':'')} key={item.id} onClick={()=>act(()=>choose(item))}><span className="finding-label"><span className="badge">{item.effect||item.class}</span><AuditMarks progress={item.progress}/></span><strong>{item.root||item.crate_name}</strong><small>{item.reason}</small></button>)}{isOpen&&loading&&<div className="loading" role="status">Loading findings…</div>}{isOpen&&loadError&&<div role="alert">{loadError}<button onClick={()=>void loadRows(key)}>Retry</button></div>}{isOpen&&rows&&rows.length<count&&<button className="load-more" disabled={loading} onClick={()=>void loadRows(key,true)}>Load more ({rows.length} of {count})</button>}</div></section>;
      })}{listResult===listKey&&listFailure&&<div role="alert">{listFailure}<button onClick={()=>setListRetry(value=>value+1)}>Retry findings</button></div>}{listResult===listKey&&!listLoading&&!listFailure&&!groups.length&&<div className="empty">{status.running?'Analyzing the workspace…':status.status==='complete'?'No matching findings.':'No findings available. Check analysis output.'}</div>}</div>
      <div className="pagination"><button aria-label={inverted?'Previous effect sources':'Previous files'} disabled={page===0} onClick={()=>setPage(p=>p-1)}>←</button><span>{inverted?'Effect sources':'Files'} · {page+1} / {Math.max(1,Math.ceil(totalGroups/100))}</span><button aria-label={inverted?'Next effect sources':'Next files'} disabled={(page+1)*100>=totalGroups} onClick={()=>setPage(p=>p+1)}>→</button></div>
    </aside><PanelDivider side="left" size={leftWidth} onResize={setLeftWidth}/></div>
    <main aria-busy={opening}><div className="toolbar"><button disabled={!nav.length||busy} onClick={()=>act(async()=>{const previous=nav[nav.length-1];if(await open(previous,false))setNav(n=>n.slice(0,-1));})}>← Back</button><span className="filename" title={buffer?.path}>{buffer?displaySourcePath(buffer.path,root):'Source workspace'}</span>{opening&&<span className="navigation-loading" role="status">Opening source…</span>}{buffer?.writable&&<span className="save-status" role="status" aria-label="Source save status">{saveState.status==='failed'?'Save failed':saveState.status==='saving'?'Saving…':saveState.status==='pending'?'Unsaved changes':'Saved'}</span>}</div>
      {saveState.status==='failed'&&<div className="error source-save-error" role="alert"><span>{saveState.error}</span><button disabled={busy} onClick={()=>act(()=>saver.current!.retry())}>Retry</button><button disabled={busy} onClick={()=>act(()=>navigator.clipboard.writeText(saver.current!.text))}>Copy edits</button><button disabled={busy} onClick={()=>act(reloadSource)}>Reload file</button></div>}
      {buffer?<><div className="buffer-state"><span className="navigation-status">{navigationStatus}</span>{buffer.writable?'Workspace source':'Read-only dependency'}{(status.running||startingAnalysis)&&buffer.writable?' · Editing paused during analysis':''}</div>
      <Editor locked={status.running||startingAnalysis} reloadKey={reloadKey} onFlush={flushSource} navigation={navigation} onReady={editorReady} buffer={buffer} location={target} onChange={changeSource} onSelectionChange={setEditorSelection} finding={selected} enabled={!status.running&&!startingAnalysis} onError={setError} onOverride={t=>act(()=>openOverride(t))} prepare={async t=>{
        const finding=selectedRef.current;
        if(!finding)throw Error('Select a finding before inserting documentation.');
        await saver.current!.flush();
        if(selectedRef.current?.id!==finding.id)throw Error('The selected finding changed. Try again.');
        const snapshot=saver.current!.snapshot;
        if(!snapshot)throw Error('Open the source file before inserting documentation.');
        return api('template',{id:finding.id,action:t.action,revision:snapshot.revision});
      }}/>
      <footer><small>{buffer.writable?'Changes save automatically after a short pause. Reanalyze to update findings.':savedOverride?`Saved to ${savedOverride} · Reanalyze to update findings`:'Save in the documentation popup writes directly to an override file.'}</small></footer></>:null}

    </main>
    <div className="side-pane right-pane" id="details-panel"><PanelDivider side="right" size={rightWidth} onResize={setRightWidth}/><aside className="details" aria-label="Effect details">{selected?<><section className="effect-summary" aria-label="Selected effect"><div className="section-title">FINDING DETAILS</div><p>{selected.reason}</p><small>{selected.crate_name} · trace {selected.trace_id||'unavailable'}</small></section>
      <div className="details-scroll" ref={detailsScroll} tabIndex={0} aria-label="Navigation and call trace"><h3>Navigate</h3>{[['Report root','root'],['Effect source','source'],['Contract','contract']].map(([label,kind])=><button className="link" key={label} disabled={!destination(selected,kind as 'source'|'root'|'contract')?.available} onClick={()=>act(()=>navigateFinding(kind as 'source'|'root'|'contract'))}>{label}{!destination(selected,kind as 'source'|'root'|'contract')?.available?' · unavailable':''}</button>)}
      {buffer&&!buffer.writable&&<p className="hint">Dependency source is read-only. Contract documentation can be supplied through an override file.</p>}
      {selected.audit&&!selected.audit.targets.length&&<p className="hint">No verified documentation attachment location is available. Inspect the source and edit manually where appropriate.</p>}
      {status.override_error?<p className="hint" role="alert">{status.override_error}</p>:null}
      {target?.approximate?<p className="hint" role="status">Approximate location; reanalyze to refresh.</p>:null}
      {unsaved||status.stale?<p className="hint">Findings are outdated. Reanalyze to refresh them.</p>:null}
      <h3>Call trace</h3><ol className="trace" reversed={inverted}>{traceEntries.map(({step,i})=><li key={i} value={i+1}><button className={highlightedTraceIndex===i?'active':''} aria-current={highlightedTraceIndex===i?'location':undefined} disabled={!step.location?.available} onClick={()=>act(()=>navigateFinding(i))}>{step.caller}<span>{step.kind} → {step.target||'effect operation'}</span><small title={step.location?.path}>{!step.location?'':displaySourcePath(step.location.path,root)}{step.location?.line?':'+step.location.line:''}{!step.location?.available?' · source unavailable':step.location.approximate?' · approximate':''}</small></button></li>)}</ol></div>
    </>:<div className="empty">Select a finding to inspect its contract and call trace.</div>}</aside></div></div>
    {overrideEditor&&<OverridePanel title={createFile?'Create override file':overrideEditor.action==='justification'?'Justify via override':'Propagate obligations via override'} step={createFile?'create':confirmRemoval?'remove':'edit'} onClose={()=>{if(!busy){if(createFile)setCreateFile(false);else setOverrideEditor(undefined);}}}>
      {!createFile?<>
      {error&&<p role="alert">{error}</p>}
      {confirmRemoval?<>
        <p className="override-removal">Remove this saved override from <strong>{overrideEditor.saved_destination}</strong>?</p>
        <p>Only this annotation will be removed. Reanalyze to update findings.</p>
        <div className="modal-actions"><button disabled={busy} onClick={()=>setConfirmRemoval(false)}>Cancel</button><button disabled={busy||status.running} onClick={()=>act(removeOverride)}>Confirm removal</button></div>
      </>:<>
      {overrideEditor.action==='justification'&&overrideEditor.obligation_documentation&&<ObligationDocumentationPanel documentation={overrideEditor.obligation_documentation}/>}
      <textarea ref={placeCaretAtEnd} autoFocus disabled={busy} aria-label="Override documentation" value={overrideEditor.document} onChange={e=>setOverrideEditor({...overrideEditor,document:e.target.value})}/>
      <label className="override-destination">Override file{overrideEditor.destinations.length>1?<select aria-label="Override file" value={overrideEditor.destination} disabled={busy} onChange={e=>setOverrideEditor({...overrideEditor,destination:e.target.value})}>{overrideEditor.destinations.map(d=><option key={d.path} value={d.path}>{d.path}</option>)}</select>:<small>{overrideEditor.destination}</small>}</label>
      <div className="modal-actions">{overrideEditor.can_remove&&<button disabled={busy||status.running} onClick={()=>setConfirmRemoval(true)}>Remove override</button>}<button disabled={busy} onClick={()=>setOverrideEditor(undefined)}>Cancel</button><button className="primary" disabled={busy||status.running} onClick={()=>act(async()=>{if(!overrideEditor.destinations.find(d=>d.path===overrideEditor.destination)?.exists){setCreateFile(true);return;}await commitOverride();})}>Save</button></div>
      </>}
      </>:<>
      {error&&<p role="alert">{error}</p>}
      <p>Choose a name for the override file. It will be saved beside the active configuration.</p>
      <label className="override-destination">Filename<input autoFocus aria-label="Override filename" value={overrideFilename} disabled={busy} onChange={e=>setOverrideFilename(e.target.value)}/></label>
      <div className="modal-actions"><button disabled={busy} onClick={()=>setCreateFile(false)}>Cancel</button><button className="primary" disabled={busy||status.running||!overrideFilename.trim()} onClick={()=>act(()=>commitOverride(overrideFilename))}>Create &amp; save</button></div>
      </>}
    </OverridePanel>}
    <div className="analysis-log"><button onClick={()=>setLogs(!logs)}>{logs?'▾':'▸'} Analysis output</button><span>{status.count} findings</span>{logs&&<pre>{status.log||'Waiting for analysis output…'}</pre>}</div>
  </div>;
}
createRoot(document.getElementById('root')!).render(<App/>);
