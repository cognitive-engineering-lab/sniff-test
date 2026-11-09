import React, {useEffect, useLayoutEffect, useRef, useState} from 'react';
import {createRoot} from 'react-dom/client';
import {EditorView, basicSetup} from 'codemirror';
import {EditorState, StateField, StateEffect} from '@codemirror/state';
import {Decoration, WidgetType} from '@codemirror/view';
import {rust, rustLanguage} from '@codemirror/lang-rust';
import './style.css';
import {Navigation, filePath} from './navigation';

type Location = {path:string; start:number; end:number; available:boolean; hash?:string; line?:number; live?:boolean};
type Buffer = {path:string; content:string; original:string; revision:number; writable:boolean; conflict:boolean; annotations?:OverrideDraft[]};
type OverrideDraft = {annotation:{effect:string; action:string; document:string; selector:unknown}; location:Location; applied:boolean; previous_document?:string|null};
type Target = {action:string; location:Location; selector?:unknown; annotationIndex?:number};
function sameSelector(a:unknown,b:unknown) {
  if(!a||!b)return false;
  const left=a as Record<string,unknown>,right=b as Record<string,unknown>;
  return ['namespace','crate-name','version','source-path','source-hash','start','end','kind','site'].every(key=>left[key]===right[key]);
}
type OverridePlan = {token:string; destination:string; destinations:string[]; existing:boolean; diff:string};
type TemplateEdit = {path:string; revision:number; start:number; end:number; text:string; cursor:number};
type EditorSelection = {path:string; from:number; to:number};
type Finding = {id:string; crate_name:string; effect?:string;kind:string;class?:string;level:string;root?:string;trace_id?:string;reason:string;requirements:string[];missing_requirements:string[];display_trace:string[]; audit?:{obligation:string; justification:string; source?:Location; root?:Location; contract?:Location; targets:Target[]; trace:{caller:string; target?:string; kind:string; location?:Location}[]}};
type Summary = {id:string; crate_name:string; root:string; reason:string; level:string; effect:string; class:string; path?:string};
type FindingGroup = {key:string; label?:string; count:number; items:Summary[]};
type Status = {generation:number; running:boolean; stale:boolean; status:string; count:number; log:string};
const token = location.hash.slice(1) || sessionStorage.getItem('audit-token') || '';
if (token) { sessionStorage.setItem('audit-token', token); history.replaceState(null, '', location.pathname); }
async function api(path:string, body?:unknown) {
  const response = await fetch('/api/v1/'+path, {method:body === undefined ? 'GET' : 'POST', headers:{'x-audit-token':token, 'Content-Type':'application/json'}, body:body === undefined ? undefined : JSON.stringify(body)});
  if (!response.ok) { const text = await response.text(); let error; try { error = JSON.parse(text).error; } catch {} throw Error(error || `Request failed (${response.status})`); }
  return response.json();
}
const setPromptsEnabled = StateEffect.define<boolean>();
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
function Editor({buffer, location:target, onChange, onSelectionChange, finding, enabled, prepare, onOverride, onError, navigation, onReady}:{buffer:Buffer; location?:Location; onChange:(text:string)=>void; onSelectionChange:(selection?:EditorSelection)=>void; finding?:Finding; enabled:boolean; prepare:(target:Target)=>Promise<TemplateEdit>; onOverride:(target:Target)=>void; onError:(error:string)=>void; navigation?:Navigation; onReady:(view:EditorView|undefined)=>void}) {
  const holder = useRef<HTMLDivElement>(null), editorRef=useRef<EditorView | undefined>(undefined);
  const callback = useRef(onChange); callback.current = onChange;
  const selectionRef=useRef(onSelectionChange);selectionRef.current=onSelectionChange;
  const prepareRef=useRef(prepare);prepareRef.current=prepare;
  const overrideRef=useRef(onOverride);overrideRef.current=onOverride;
  const errorRef=useRef(onError);errorRef.current=onError;
  const readyRef=useRef(onReady);readyRef.current=onReady;
  useEffect(()=>{
    if (!holder.current) return;
    let active=true;
    let view:EditorView;
    const syntax=rustLanguage.parser.parse(buffer.content);
    const annotations=buffer.annotations || [];
    const targets=finding?.audit?.targets || [];
    const resolved=targets.some(t=>annotations.some(a=>a.annotation.effect===finding?.effect && a.annotation.action===t.action && sameSelector(a.annotation.selector,t.selector)));
    const pendingTargets=targets.filter(t=>!t.selector || !resolved);
    const completedTargets:Target[]=annotations.map((a,annotationIndex)=>({action:a.annotation.action,location:a.location,selector:a.annotation.selector,annotationIndex}));
    const widgets=(!buffer.conflict && buffer.content===buffer.original ? [...pendingTargets,...completedTargets] : []).filter(t=>(buffer.writable || t.selector) && t.location.path===buffer.path && t.location.available).flatMap(t=>{
      const position=bytePosition(buffer.content,t.location.start);
      // Attributes wrap their item in the Rust syntax tree. Only move the
      // item's own prompt, never a prompt for an operation inside its body.
      let anchor=position;
      let node:ReturnType<typeof syntax.resolveInner>|null=syntax.resolveInner(position,1);
      for(;node;node=node.parent){
        if(node.from===position && node.parent?.name==='AttributeItem')anchor=node.parent.from;
      }
      const lineStart=buffer.content.lastIndexOf('\n',anchor-1)+1;
      if(!t.selector && buffer.content.slice(buffer.content.lastIndexOf('\n',position-1)+1,position).trim())return [];
      const added=t.annotationIndex===undefined?undefined:annotations[t.annotationIndex];
      const widget=new DocumentationPrompt(t.action,()=>{
        if(t.selector){overrideRef.current(t);return;}
        const snapshot=view.state.sliceDoc();
        prepareRef.current(t).then(edit=>{
          if(!active)return;
          if(view.state.sliceDoc()!==snapshot || edit.path!==buffer.path || edit.revision!==buffer.revision)throw Error('Source changed while preparing the template. Reanalyze before retrying.');
          const from=bytePosition(snapshot,edit.start),to=bytePosition(snapshot,edit.end);
          const updated=snapshot.slice(0,from)+edit.text+snapshot.slice(to);
          const cursor=editorPosition(updated,edit.cursor);
          view.dispatch({changes:edit.text?{from:editorPosition(snapshot,edit.start),to:editorPosition(snapshot,edit.end),insert:edit.text}:undefined,selection:{anchor:cursor},effects:EditorView.scrollIntoView(cursor,{y:'center'}),userEvent:'input'});
          view.focus();
        }).catch(e=>{if(active)errorRef.current(String(e));});
      },!!t.selector,added?(added.applied?'Override applied':'Draft saved'):'');
      return [Decoration.widget({widget,block:true,side:-1}).range(buffer.content.slice(0,lineStart).replace(/\r\n/g,'\n').length)];
    });
    const originalPrompts=Decoration.set(widgets,true);
    const prompts=StateField.define({
      create:()=>({enabled,decorations:enabled?originalPrompts:Decoration.none}),
      update:(value,tr)=>{
        let allowed=value.enabled;
        for(const effect of tr.effects)if(effect.is(setPromptsEnabled))allowed=effect.value;
        if(!tr.docChanged && allowed===value.enabled)return value;
        return {enabled:allowed,decorations:allowed && tr.newDoc.toString()===buffer.original.replace(/\r\n/g,'\n')?originalPrompts:Decoration.none};
      },
      provide:field=>EditorView.decorations.from(field,value=>value.decorations),
    });
    view = new EditorView({parent:holder.current, state:EditorState.create({doc:buffer.content, extensions:[basicSetup,EditorState.lineSeparator.of(buffer.original.includes('\r\n')?'\r\n':'\n'),rust(),prompts,navigation?.extension(buffer.path) || [], EditorView.lineWrapping, EditorState.readOnly.of(!buffer.writable), EditorView.updateListener.of(u=>{
      if(u.docChanged)callback.current(u.state.sliceDoc());
      if(u.selectionSet || u.docChanged){const {from,to}=u.state.selection.main;selectionRef.current({path:buffer.path,from,to});}
    })]})});
    editorRef.current=view;
    selectionRef.current({path:buffer.path,from:view.state.selection.main.from,to:view.state.selection.main.to});
    readyRef.current(view);
    return ()=>{active=false;readyRef.current(undefined);selectionRef.current(undefined);editorRef.current=undefined;view.destroy();};
  },[buffer.path,buffer.revision,finding?.id,navigation]);
  useEffect(()=>{
    const view=editorRef.current;
    if(!view || !target?.available || target.path!==buffer.path)return;
    if(!target.live && buffer.content!==buffer.original)return;
    const source=view.state.sliceDoc();
    const from=editorPosition(source,target.start),to=editorPosition(source,target.end);
    if(from<=to && to<=view.state.doc.length){view.dispatch({selection:{anchor:from,head:to},effects:EditorView.scrollIntoView(from,{y:'center'})});view.focus();}
  },[target,buffer.path,buffer.revision,navigation,finding?.id]);
  useEffect(()=>{editorRef.current?.dispatch({effects:setPromptsEnabled.of(enabled)});},[enabled]);
  return <div className="editor" ref={holder} aria-label="Rust source editor"/>;
}
function placeCaretAtEnd(element:HTMLTextAreaElement|null) {
  if(element)element.setSelectionRange(element.value.length,element.value.length);
}
function Modal({title,children,onClose}:{title:string;children:React.ReactNode;onClose:()=>void}) {
  const ref=useRef<HTMLDialogElement>(null);
  useEffect(()=>{const prior=document.activeElement as HTMLElement|null;ref.current?.showModal();return()=>{ref.current?.close();prior?.focus();};},[]);
  return <dialog ref={ref} aria-label={title} onCancel={e=>{e.preventDefault();onClose();}}><h2>{title}</h2>{children}</dialog>;
}
function App() {
  const [root,setRoot]=useState(''); const [status,setStatus]=useState<Status>({generation:0,running:false,stale:true,status:'connecting',count:0,log:''});
  const [groups,setGroups]=useState<FindingGroup[]>([]),[total,setTotal]=useState(0),[totalGroups,setTotalGroups]=useState(0),[effects,setEffects]=useState<string[]>([]);
  const [inverted,setInverted]=useState(false);
  const [expanded,setExpanded]=useState<Set<string>>(()=>new Set());
  const [sourceExpanded,setSourceExpanded]=useState<Set<string>>(()=>new Set());
  const [query,setQuery]=useState(''),[effect,setEffect]=useState(''),[level,setLevel]=useState(''),[kind,setKind]=useState(''),[page,setPage]=useState(0);
  const [selected,setSelected]=useState<Finding>(),[buffer,setBuffer]=useState<Buffer>(),[text,setText]=useState(''),[target,setTarget]=useState<Location>();
  const [drafts,setDrafts]=useState<Buffer[]>([]),[diff,setDiff]=useState(''),[view,setView]=useState<'source'|'changes'>('source');
  const [error,setError]=useState(''),[busy,setBusy]=useState(false),[logs,setLogs]=useState(false);
  const [nav,setNav]=useState<Location[]>([]);
  const [overrideEditor,setOverrideEditor]=useState<{id?:string;path?:string;index?:number;generation?:number;action:string;revision:number;document:string;applied?:boolean;previous_document?:string|null}>();
  const [overridePlan,setOverridePlan]=useState<OverridePlan>();
  const [editorSelection,setEditorSelection]=useState<EditorSelection>();
  const [navigation,setNavigation]=useState<Navigation>(),[navigationStatus,setNavigationStatus]=useState('');
  const editor=useRef<EditorView|undefined>(undefined);
  const waitingEditor=useRef<{path:string;resolve:(view:EditorView|null)=>void}|undefined>(undefined);
  function editorReady(view:EditorView|undefined){editor.current=view;if(view && waitingEditor.current && waitingEditor.current.path===buffer?.path){waitingEditor.current.resolve(view);waitingEditor.current=undefined;}}
  const rememberDefinition=useRef<(view:EditorView)=>void>(()=>{});
  rememberDefinition.current=view=>rememberPosition(view);
  const displayDefinition=useRef<(uri:string)=>Promise<EditorView|null>>(async()=>null);
  displayDefinition.current=async(uri)=>{
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
  useEffect(()=>{for(const draft of drafts)navigation?.document(draft.path,draft.content);},[drafts,navigation]);
  useEffect(()=>{
    if(!navigation || status.running)return;
    let cancelled=false;
    // Closed editors retain draft overlays; refresh them after source is reanalyzed.
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
  async function act(work:()=>Promise<void>) {setBusy(true);setError('');try{await work();}catch(e){setError(String(e));}finally{setBusy(false);}}

  async function refreshDrafts(){setDrafts(await api('drafts'));}
  async function save(){if(!buffer)return; const updated=await api('buffer',{path:buffer.path,revision:buffer.revision,content:text});setBuffer(updated);await refreshDrafts();return updated as Buffer;}
  function rememberPosition(view:EditorView|undefined){
    if(!buffer || !view)return;
    const state=view.state,selection=state.selection.main;
    setNav(n=>[...n,{path:buffer.path,start:new TextEncoder().encode(state.sliceDoc(0,selection.from)).length,end:new TextEncoder().encode(state.sliceDoc(0,selection.to)).length,available:true,live:true}]);
  }
  async function open(loc:Location, remember=true){
    if(unsaved)await save();
    if(remember)rememberPosition(editor.current);
    const next=await api('buffer?'+new URLSearchParams({path:loc.path}));let destination=loc;
    if(loc.available && loc.hash){
      const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(next.original));
      const hash=Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,'0')).join('');
      if(hash!==loc.hash){destination={...loc,available:false};setError('Source changed since analysis. Reanalyze to restore precise navigation.');}
    }
    if(loc.available && !loc.live && next.content!==next.original){destination={...loc,available:false};setError('This draft differs from analyzed source. Apply or discard it to restore call-site positioning.');}
    if(!loc.available && loc.hash)setError('The recorded source range could not be verified. Reanalyze or restore the original source.');
    if(waitingEditor.current?.path===loc.path){
      waitingEditor.current.path=next.path;
      if(buffer && buffer.path===next.path && editor.current && buffer.revision===next.revision){waitingEditor.current.resolve(editor.current);waitingEditor.current=undefined;}
    }
    setBuffer(next);setText(next.content);setTarget({...destination,path:next.path});setView('source');setDiff('');
  }
  async function choose(item:Summary){const f:Finding=await api('finding?'+new URLSearchParams({id:item.id}));setSelected(f);const loc=[f.audit?.source,f.audit?.root].find(l=>l?.available);if(loc)await open(loc);}
  useEffect(()=>{api('workspace').then(v=>setRoot(v.root)).catch(e=>setError(String(e)));refreshDrafts().catch(e=>setError(String(e)));
    const controller=new AbortController();
    (async()=>{try{
      const response=await fetch('/api/v1/events',{headers:{'x-audit-token':token},signal:controller.signal});
      if(!response.ok)throw Error('Cannot connect. Open the full URL printed by cargo sniff-test.');
      const reader=response.body!.getReader(),decoder=new TextDecoder();let pending='';
      while(true){const {done,value}=await reader.read();if(done)break;pending+=decoder.decode(value,{stream:true});let boundary;
        while((boundary=pending.indexOf('\n\n'))>=0){const event=pending.slice(0,boundary);pending=pending.slice(boundary+2);const data=event.split('\n').find(l=>l.startsWith('data:'));if(data)setStatus(JSON.parse(data.slice(5)));}}
    }catch(e){if(!controller.signal.aborted)setError(String(e));}})();return()=>controller.abort();
  },[]);
  useEffect(()=>{
    let cancelled=false;
    api('findings?'+new URLSearchParams({q:query,effect,level,class:kind,grouped:'true',group_by:inverted?'effect-source':'file',offset:String(page*100)})).then(value=>{
      if(cancelled)return;
      const lastPage=Math.max(0,Math.ceil(value.total_groups/100)-1);
      if(page>lastPage){setPage(lastPage);return;}
      setGroups(value.groups);setTotal(value.total);setTotalGroups(value.total_groups);setEffects(value.effects);
    }).catch(e=>{if(!cancelled)setError(String(e));});
    return ()=>{cancelled=true;};
  },[query,effect,level,kind,inverted,page,status.generation,status.running]);
  useEffect(()=>{if(!status.running)refreshDrafts().catch(e=>setError(String(e)));},[status.generation,status.running]);
  useEffect(()=>{setSelected(undefined)},[status.generation]);
  useEffect(()=>{const warn=(e:BeforeUnloadEvent)=>{if(unsaved||overrideEditor){e.preventDefault();}};window.addEventListener('beforeunload',warn);return()=>window.removeEventListener('beforeunload',warn)},[unsaved,overrideEditor]);
  async function review(draft?:Buffer){if(unsaved&&draft&&draft.path!==buffer?.path)await save();let b=draft||buffer;if(!b)return;if(unsaved&&buffer?.path===b.path)b=await save()||b;setBuffer(b);setText(b.content);setDiff((await api('diff?'+new URLSearchParams({path:b.path}))).diff);setView('changes');}

  const trace=selected?.audit?.trace||[];
  const traceEntries=trace.map((step,i)=>({step,i}));
  if(inverted)traceEntries.reverse();
  const activeTraceIndex=view==='source' && buffer && !unsaved && buffer.content===buffer.original && editorSelection?.path===buffer.path
    ? trace.findIndex(step=>{
      const loc=step.location;
      if(!loc?.available || loc.path!==buffer.path)return false;
      const from=editorPosition(buffer.original,loc.start),to=editorPosition(buffer.original,loc.end);
      return editorSelection.from===from && editorSelection.to===to;
    }) : -1;
  const activeTraceCaretIndex=activeTraceIndex<0 && view==='source' && buffer && !unsaved && buffer.content===buffer.original && editorSelection?.path===buffer.path && editorSelection.from===editorSelection.to
    ? trace.findIndex(step=>{
      const loc=step.location;
      if(!loc?.available || loc.path!==buffer.path)return false;
      const from=editorPosition(buffer.original,loc.start),to=editorPosition(buffer.original,loc.end);
      return from<=editorSelection.from && editorSelection.from<(to===from?to+1:to);
    }) : -1;
  const highlightedTraceIndex=activeTraceIndex>=0?activeTraceIndex:activeTraceCaretIndex;
  return <div className="app">
    <header><div className="brand"><b>sniff-test</b><span> / audit</span></div><span className="workspace" title={root}>{root}</span><span className={'status '+status.status}>{status.status}{status.stale?' · stale':''}</span><button disabled={status.running||busy} onClick={()=>act(async()=>{await api('analysis',{});})}>↻ Reanalyze</button></header>
    {error&&<div className="error" role="alert">{error}<button onClick={()=>setError('')}>Dismiss</button></div>}
    <div className="layout"><aside className="findings"><div className="section-title">FINDINGS <span>{total}</span></div>
      <button type="button" className="invert-effect" aria-pressed={inverted} onClick={()=>{setInverted(value=>!value);setPage(0);}}>⇄ Invert effect</button>
      <input aria-label={inverted?'Search effect sources':'Search findings'} placeholder={inverted?'Search effect sources…':'Search files, roots, crates…'} value={query} onChange={e=>{setQuery(e.target.value);setPage(0);}}/>
      <div className="filters"><select aria-label="Effect" value={effect} onChange={e=>{setEffect(e.target.value);setPage(0);}}><option value="">All effects</option>{effects.map(e=><option key={e}>{e}</option>)}</select><select aria-label="Severity" value={level} onChange={e=>{setLevel(e.target.value);setPage(0);}}><option value="">All levels</option><option>warn</option><option>deny</option></select></div>
      <select aria-label="Finding class" value={kind} onChange={e=>{setKind(e.target.value);setPage(0);}}><option value="">All finding classes</option>{['concrete-operation','concrete-invocation','documented-obligation','undocumented-invocation','unresolved-call-target','analysis-incomplete','ambiguous-marker','ambiguous-requirement'].map(k=><option key={k}>{k}</option>)}</select>
      <div className="finding-list">{groups.map(({key, label,items:rows,count},index)=>{
        const path=label||key;
        const isOpen=(inverted?sourceExpanded:expanded).has(key),listId=`${inverted?'source':'file'}-findings-${index}`;
        return <section key={key}><button type="button" className="group" title={path} aria-expanded={isOpen} aria-controls={listId} onClick={()=>(inverted?setSourceExpanded:setExpanded)(previous=>{const next=new Set(previous);if(next.has(key))next.delete(key);else next.add(key);return next;})}><span className="group-chevron" aria-hidden="true">{isOpen?'▾':'▸'}</span><span className="group-path">{inverted?path.replace(root+'/',''):path.startsWith(root+'/')?path.slice(root.length+1):path}</span><span className="group-count" aria-label={`${count} ${inverted?'reports':'effects'}`} >{count}</span></button><div id={listId} hidden={!isOpen}>{isOpen&&rows.map(item=><button className={'finding '+(selected?.id===item.id?'selected':'')} key={item.id} onClick={()=>act(()=>choose(item))}><span className="badge">{item.effect||item.class}</span><strong>{item.root||item.crate_name}</strong><small>{item.reason}</small></button>)}</div></section>;
      })}{!groups.length&&<div className="empty">{status.running?'Analyzing the workspace…':status.status==='complete'?'No matching findings.':'No findings available. Check analysis output.'}</div>}</div>
      <div className="pagination"><button aria-label={inverted?'Previous effect sources':'Previous files'} disabled={page===0} onClick={()=>setPage(p=>p-1)}>←</button><span>{inverted?'Effect sources':'Files'} · {page+1} / {Math.max(1,Math.ceil(totalGroups/100))}</span><button aria-label={inverted?'Next effect sources':'Next files'} disabled={(page+1)*100>=totalGroups} onClick={()=>setPage(p=>p+1)}>→</button></div>
      <div className="section-title">SAVED DRAFTS <span>{drafts.length}</span></div>{drafts.map(d=><button className="draft" key={d.path} onClick={()=>act(()=>review(d))}>{d.path.replace(root+'/','')}{d.conflict?' · conflict':d.writable?' · modified':' · override draft'}</button>)}
    </aside>
    <main><div className="toolbar"><button disabled={!nav.length||busy} onClick={()=>act(async()=>{const previous=nav[nav.length-1];setNav(n=>n.slice(0,-1));await open(previous,false);})}>← Back</button><span className="filename">{buffer?.path.replace(root+'/','')||'Source workspace'}</span>{buffer&&<><button onClick={()=>setView('source')}>Source</button><button onClick={()=>act(()=>review())}>Review diff</button></>}</div>
      {buffer?<><div className="buffer-state"><span className="navigation-status">{navigationStatus}</span>{buffer.writable?'Workspace source':'Read-only dependency'}{unsaved?' · unsaved editor changes':buffer.content!==buffer.original?' · draft saved':''}{buffer.conflict&&<strong> · External file changed. Copy your draft, discard it, then reapply your changes to the current source.</strong>}</div>
      {view==='source'?<Editor navigation={navigation} onReady={editorReady} buffer={buffer} location={target} onChange={setText} onSelectionChange={setEditorSelection} finding={selected} enabled={!status.running&&!status.stale&&!unsaved} onError={setError} onOverride={t=>act(async()=>{if(!buffer)return;if(t.annotationIndex!==undefined){const a=buffer.annotations![t.annotationIndex];setOverrideEditor({path:buffer.path,index:t.annotationIndex,action:a.annotation.action,revision:buffer.revision,document:a.annotation.document,applied:a.applied,previous_document:a.previous_document});return;}if(!selected)return;const result=await api('override/template',{id:selected.id,action:t.action,revision:buffer.revision});setOverrideEditor({id:selected.id,action:t.action,revision:buffer.revision,generation:result.generation,document:result.document});})} prepare={async t=>{
        if(!selected||!buffer||unsaved)throw Error('Save or discard editor changes before inserting a template.');
        return api('template',{id:selected.id,action:t.action,revision:buffer.revision});
      }}/>:<pre className="diff">{(!buffer.writable?'Override preview — dependency source stays unchanged\n\n':'')+(diff||'No changes to review.')}</pre>}
      <footer>{view==='source'?<button className="primary" disabled={!buffer.writable||!unsaved||busy||status.running} onClick={()=>act(async()=>{await save();})}>Save draft</button>:<button className="primary" disabled={buffer.conflict||!diff||busy||status.running} onClick={()=>act(async()=>{if(!buffer.writable){setOverridePlan(await api('override/prepare',{path:buffer.path,revision:buffer.revision}));return;}await api('apply',{path:buffer.path,revision:buffer.revision});await open({path:buffer.path,start:0,end:0,available:true});await refreshDrafts();})}>{buffer.writable?'Apply file & reanalyze':'Apply overrides & reanalyze'}</button>}<button disabled={busy||status.running||(buffer.content===buffer.original&&!buffer.annotations?.some(a=>!a.applied))} onClick={()=>act(async()=>{await api('discard',{path:buffer.path,revision:buffer.revision});await open({path:buffer.path,start:0,end:0,available:true});await refreshDrafts();})}>Discard draft</button><small>{buffer.writable?'Drafts stay separate from source until applied.':'Apply writes override documentation; dependency source stays read-only.'}</small></footer></>:null}
    </main>
    <aside className="details" aria-label="Effect details">{selected?<><section className="effect-summary" aria-label="Selected effect"><div className="section-title">FINDING DETAILS</div><p>{selected.reason}</p><small>{selected.crate_name} · trace {selected.trace_id||'unavailable'}</small></section>
      <div className="details-scroll" ref={detailsScroll} tabIndex={0} aria-label="Navigation and call trace"><h3>Navigate</h3>{[['Report root',selected.audit?.root],['Effect source',selected.audit?.source],['Contract',selected.audit?.contract]].map(([label,l])=><button className="link" key={label as string} disabled={!l || !(l as Location).available} onClick={()=>act(()=>open(l as Location))}>{label as string}{!(l as Location)?.available?' · unavailable':''}</button>)}
      {buffer&&!buffer.writable&&<p className="hint">Dependency source is read-only. Contract documentation can be supplied through an override file.</p>}
      {selected.audit&&!selected.audit.targets.length&&<p className="hint">No verified documentation attachment location is available. Inspect the source and edit manually where appropriate.</p>}
      {unsaved||buffer?.content!==buffer?.original?<p className="hint">Revert to the original source to restore inline prompts, or apply edits and reanalyze.</p>:null}
      <h3>Call trace</h3><ol className="trace" reversed={inverted}>{traceEntries.map(({step,i})=><li key={i} value={i+1}><button className={highlightedTraceIndex===i?'active':''} aria-current={highlightedTraceIndex===i?'location':undefined} disabled={!step.location?.available} onClick={()=>act(()=>open(step.location!))}>{step.caller}<span>{step.kind} → {step.target||'effect operation'}</span><small title={step.location?.path}>{!step.location?'':step.location.path.startsWith(root+'/')?step.location.path.slice(root.length+1):'…/'+step.location.path.split('/').slice(-3).join('/')}{step.location?.line?':'+step.location.line:''}{!step.location?.available?' · source unavailable':''}</small></button></li>)}</ol></div>
    </>:<div className="empty">Select a finding to inspect its contract and call trace.</div>}</aside></div>
    {overrideEditor&&<Modal title={overrideEditor.action==='justification'?'Justify via override':'Propagate obligations via override'} onClose={()=>setOverrideEditor(undefined)}>
      {error&&<p role="alert">{error}</p>}<p>Justifications save marker text at the callsite line. Obligations save replacement rustdoc at the definition line, preserving other contracts.</p>
      <textarea ref={placeCaretAtEnd} autoFocus aria-label="Override documentation" value={overrideEditor.document} onChange={e=>setOverrideEditor({...overrideEditor,document:e.target.value})}/>
      <div className="modal-actions">{overrideEditor.index!==undefined&&!overrideEditor.applied&&<button disabled={busy||status.running} onClick={()=>act(async()=>{const result=await api('override/discard',overrideEditor);setBuffer(result.buffer);setText(result.buffer.content);if(result.finding)setSelected(result.finding);setOverrideEditor(undefined);await refreshDrafts();})}>{overrideEditor.previous_document?'Discard changes':'Delete draft'}</button>}<button onClick={()=>setOverrideEditor(undefined)}>Cancel</button><button className="primary" disabled={busy||status.running} onClick={()=>act(async()=>{const next=await api(overrideEditor.id?'override/save':'override/edit',overrideEditor);setBuffer(next);setText(next.content);setOverrideEditor(undefined);if(view==='changes')setDiff((await api('diff?'+new URLSearchParams({path:next.path}))).diff);await refreshDrafts();})}>Save draft</button></div>
    </Modal>}
    {overridePlan&&buffer&&<Modal title={overridePlan.existing?'Confirm editing override file':'Apply override drafts'} onClose={()=>setOverridePlan(undefined)}>
      {error&&<p role="alert">{error}</p>}<p>{overridePlan.existing?'Applying these drafts will edit the existing override file.':'Applying these drafts will create and register an override file.'}</p>
      <label>Override file<select aria-label="Override file" value={overridePlan.destination} disabled={busy} onChange={e=>{const destination=e.target.value;act(async()=>setOverridePlan(await api('override/prepare',{path:buffer.path,revision:buffer.revision,destination})));}}>{overridePlan.destinations.map(p=><option key={p}>{p}</option>)}</select></label>
      <pre className="diff">{overridePlan.diff}</pre><div className="modal-actions"><button onClick={()=>setOverridePlan(undefined)}>Cancel</button><button className="primary" disabled={busy||status.running} onClick={()=>act(async()=>{await api('override/apply',{token:overridePlan.token,confirmed:overridePlan.existing});setOverridePlan(undefined);await open({path:buffer.path,start:0,end:0,available:true});await refreshDrafts();})}>{overridePlan.existing?'Confirm edit & reanalyze':'Create override & reanalyze'}</button></div>
    </Modal>}
    <div className="analysis-log"><button onClick={()=>setLogs(!logs)}>{logs?'▾':'▸'} Analysis output</button><span>{status.count} findings · {drafts.length} saved drafts</span>{logs&&<pre>{status.log||'Waiting for analysis output…'}</pre>}</div>
  </div>;
}
createRoot(document.getElementById('root')!).render(<App/>);
