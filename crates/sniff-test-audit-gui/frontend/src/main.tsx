import React, {useEffect, useLayoutEffect, useRef, useState} from 'react';
import {createRoot} from 'react-dom/client';
import {EditorView, basicSetup} from 'codemirror';
import {Annotation, EditorState, StateField, Compartment, Text, type ChangeDesc} from '@codemirror/state';
import {Decoration, WidgetType} from '@codemirror/view';
import {rust} from '@codemirror/lang-rust';
import {sourcePromptAttachments, continueRustComments, commentEditing, configureCommentEditing} from './source-prompts';
import './style.css';
import {Navigation, filePath} from './navigation';
import {Autosave, type SaveState} from './autosave';
import {displaySourcePath} from './source-path';
import {RustPrototype} from './rust-prototype';
import {ObligationDocumentationPanel, type ObligationDocumentation} from './obligation-documentation';
import {unwrapKind} from './unwrap-producer';
import {UnwrapProducerPanel} from './unwrap-producer-panel';

type CrateTrust = {crate_name:string;namespace:string;effects:{effect:string;count:number;trusted:boolean;exact:boolean}[];config_path:string;config_hash?:string;results_revision:number};
type DisplayMode = 'file'|'effect-source'|'obligation';
type Obligation = {key:string;effect:string;namespace:string;count:number;documentation?:ObligationDocumentation;declaration?:Location;trusted:boolean;config_path:string;config_hash?:string;results_revision:number};
type TrustPrompt = {location:Location;trusted:boolean;run:()=>void};
type Location = {approximate?:boolean;path:string; start:number; end:number; available:boolean; hash?:string; line?:number; live?:boolean};
type Buffer = {path:string; content:string; hash:string; revision:number; writable:boolean; saved_overrides:SavedOverride[]};
type SavedOverride = {annotation:{effect:string; action:string; document:string; obligation_documentation?:ObligationDocumentation; selector:unknown}; location:Location; destination:string};
type Target = {action:string; location:Location; selector?:unknown; overrideIndex?:number};
function sameSelector(a:unknown,b:unknown) {
  if(!a||!b)return false;
  const left=a as Record<string,unknown>,right=b as Record<string,unknown>;
  return ['namespace','crate-name','version','source-path','source-hash','start','end','kind','site'].every(key=>left[key]===right[key]);
}
type EffectContext = {effect:string;operation?:string;class?:string};
function effectContextLabel(context:EffectContext) {
  const readable=(value:string)=>value.replace(/[-_]+/g,' ').replace(/^./,letter=>letter.toUpperCase());
  return [context.effect,context.operation||context.class].filter(Boolean).map(value=>readable(value!)).join(' · ');
}
type DocumentationEditor = {producerFinding?:Finding;effect_source?:string|null;effect_context?:EffectContext;mode:'source'|'override'; finding?:string; line?:number; token:string; can_remove:boolean; saved_destination:string; document:string; obligation_documentation?:ObligationDocumentation; destination:string; destinations:{path:string;exists:boolean}[]; action:string};
type SavedSource = {buffer:Buffer; edit:{start:number;end:number;text:string}};
const acknowledgedSource=Annotation.define<boolean>();
function savedSourceChanges(state:EditorState,saved:SavedSource) {
  const source=state.sliceDoc();
  const changes=state.changes({from:editorPosition(source,saved.edit.start),to:editorPosition(source,saved.edit.end),insert:Text.of(saved.edit.text.replace(/\r\n/g,'\n').split('\n'))});
  if(changes.apply(state.doc).toString()!==saved.buffer.content.replace(/\r\n/g,'\n'))throw Error('Saved source no longer matches the editor. Reload the file.');
  return changes;
}
type EditorSelection = {path:string; from:number; to:number};
type FindingNavigation = {source?:Location;root?:Location;contract?:Location;trace:(Location|null)[]};
type Finding = {navigation?:FindingNavigation;id:string; crate_name:string; effect?:string;kind:string;class?:string;level:string;root?:string;trace_id?:string;reason:string;requirements:string[];missing_requirements:string[];display_trace:string[]; audit?:{obligation_documentation?:ObligationDocumentation;effect_context?:EffectContext;obligation:string; justification:string; source?:Location; root?:Location; contract?:Location; targets:Target[]; trace:{caller:string; target?:string; kind:string; location?:Location}[]}};
type AuditProgress = {justified:boolean;propagated:boolean};
type GroupProgress = {handled:number;total:number;justified:number;propagated:number};
type Summary = {description?:string;location_label?:string;label?:string;count?:number;progress?:AuditProgress|GroupProgress;id:string; crate_name:string; root:string; reason:string; level:string; effect:string; class:string; path?:string};
type FindingGroup = {crate_name?:string;item_count?:number;effects?:Record<string,number>;trusted?:boolean;progress?:GroupProgress;key:string; label?:string; path?:string; count:number; items?:Summary[]; rowsRevision?:string; loading?:boolean; loadError?:string};
type Status = {results_revision?:number;audit_revision?:number;override_revision?:number; override_error?:string; generation:number; running:boolean; stale:boolean; overrides_changed?:boolean; status:string; count:number; log:string};
const token = location.hash.slice(1) || sessionStorage.getItem('audit-token') || '';
if (token) { sessionStorage.setItem('audit-token', token); history.replaceState(null, '', location.pathname); }
async function api(path:string, body?:unknown, signal?:AbortSignal) {
  const response = await fetch('/api/v1/'+path, {signal, method:body === undefined ? 'GET' : 'POST', headers:{'x-audit-token':token, 'Content-Type':'application/json'}, body:body === undefined ? undefined : JSON.stringify(body)});
  if (!response.ok) { const text = await response.text(); let error; try { error = JSON.parse(text).error; } catch {} throw Error(error || `Request failed (${response.status})`); }
  return response.json();
}
const readProducerSource=(path:string):Promise<Buffer>=>api('buffer?'+new URLSearchParams({path}));
function PopupProducer({finding,navigation}:{finding?:Finding;navigation?:Navigation}) {
  const audit=finding?.audit;
  const kind=unwrapKind([audit?.obligation_documentation?.function,...(audit?.trace.map(step=>step.target)||[])]);
  const source=destination(finding,'source');
  return kind&&source?<UnwrapProducerPanel kind={kind} source={source} navigation={navigation} readSource={readProducerSource}/>:null;
}
class DocumentationPrompt extends WidgetType {
  constructor(readonly action:string, readonly run:()=>void, readonly override=false, readonly added="", readonly manual=false) { super(); }
  toDOM() {
    const element=document.createElement('div');element.className='inline-prompt';
    const button=document.createElement('button');button.type='button';
    const justify=this.action==='justification';
    const trust=this.action==='trust';
    const label=this.manual?'Needs manual justification':trust?(this.added?'Ignored':'Ignore Obligations'):this.added?(justify?'Justified!':'Obligation propagated!'):this.override?(justify?'Justify via override':'Propagate obligations via override'):(justify?'Justify here':'Propagate to callers');
    button.textContent=(trust?'✓ ':justify?'✓ ':'↑ ')+label;
    if(this.added)button.classList.add('completed');
    button.setAttribute('aria-label',label);
    button.addEventListener('click',this.run);
    const hint=document.createElement('span');
    hint.textContent=this.manual?'This layout requires a manual comment':trust?'Ignore this function’s obligations for this effect':this.added || (justify?"Explain why this is valid":"Document the caller's obligation");
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
function Editor({trustPrompt, hideDocumentation=false, buffer, locked, reloadKey, onFlush, location:target, onChange, onSelectionChange, finding, enabled, onDocumentation, navigation, onReady}: {trustPrompt?:TrustPrompt;hideDocumentation?:boolean;buffer:Buffer; locked:boolean; reloadKey:number; onFlush:()=>void; location?:Location; onChange:(text:string,changes:ChangeDesc,previous:string,acknowledged?:boolean,path?:string)=>void; onSelectionChange:(selection?:EditorSelection)=>void; finding?:Finding; enabled:boolean; onDocumentation:(target:Target)=>void; navigation?:Navigation; onReady:(view:EditorView|undefined,acknowledge?:(saved:SavedSource)=>void)=>void}) {
  const documents=useRef(new Map<string,{state:EditorState;content:string;scroll:ReturnType<EditorView['scrollSnapshot']>}>());
  const bufferRef=useRef(buffer);bufferRef.current=buffer;
  const holder = useRef<HTMLDivElement>(null), editorRef=useRef<EditorView | undefined>(undefined);
  const callback = useRef(onChange); callback.current = onChange;
  const selectionRef=useRef(onSelectionChange);selectionRef.current=onSelectionChange;
  const documentationRef=useRef(onDocumentation);documentationRef.current=onDocumentation;
  const readyRef=useRef(onReady);readyRef.current=onReady;
  const flushRef=useRef(onFlush);flushRef.current=onFlush;
  // Keep manual prompts dismissible after reformatting and autosave reconfigure the candidates.
  const manualTargets=useRef({scope:'',actions:new Set<string>()});
  const [manualMarker,setManualMarker]=useState<string>();
  function closeManualGuidance(){setManualMarker(undefined);editorRef.current?.focus();}
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
        if(update.docChanged)callback.current(update.state.sliceDoc(),update.changes,update.startState.sliceDoc(),update.transactions.some(tr=>tr.annotation(acknowledgedSource)));
        if(update.selectionSet||update.docChanged){const {from,to}=update.state.selection.main;selectionRef.current({path:bufferRef.current.path,from,to});}
      }),
    ]});
    const view=new EditorView({parent:holder.current,state});
    if(cached?.content===buffer.content)view.dispatch({effects:cached.scroll});
    editorRef.current=view;readyRef.current(view,saved=>{
      if(saved.buffer.path===bufferRef.current.path){
        if(view.state.sliceDoc()===saved.buffer.content)return;
        const changes=savedSourceChanges(view.state,saved),scroll=view.scrollSnapshot().map(changes);
        view.dispatch({changes,selection:view.state.selection.map(changes,1),effects:scroll?[scroll]:[],annotations:acknowledgedSource.of(true),userEvent:'documentation'});
      }else{
        const cached=documents.current.get(saved.buffer.path);
        if(!cached || cached.content===saved.buffer.content)return;
        try{
          const changes=savedSourceChanges(cached.state,saved);
          documents.current.set(saved.buffer.path,{content:saved.buffer.content,state:cached.state.update({changes,selection:cached.state.selection.map(changes,1),annotations:acknowledgedSource.of(true),userEvent:'documentation'}).state,scroll:cached.scroll.map(changes)!});
          callback.current(saved.buffer.content,changes,cached.content,true,saved.buffer.path);
        }catch{documents.current.delete(saved.buffer.path);}
      }
    });
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
    if(hideDocumentation){
      const loc=trustPrompt?.location;
      const valid=enabled&&loc?.available&&loc.path===buffer.path&&loc.hash===buffer.hash;
      const decorations=valid?Decoration.set([Decoration.widget({
        widget:new DocumentationPrompt('trust',trustPrompt!.run,false,trustPrompt!.trusted?'Ignored':''),block:true,side:-1,
      }).range(view.state.doc.lineAt(editorPosition(buffer.content,loc!.start)).from)]):Decoration.none;
      view.dispatch({effects:[configureCommentEditing.of({scope:'obligation',candidates:[]}),promptsConfig.current.reconfigure(EditorView.decorations.of(decorations))]});
      return;
    }
    const overrides=buffer.saved_overrides;
    const scope=JSON.stringify([buffer.path,finding?.id]);
    if(manualTargets.current.scope!==scope)manualTargets.current={scope,actions:new Set()};
    const targets=finding?.audit?.targets || [];
    const resolved=targets.some(t=>overrides.some(a=>a.annotation.effect===finding?.effect && a.annotation.action===t.action && sameSelector(a.annotation.selector,t.selector)));
    const pendingTargets=targets.filter(t=>!t.selector || !resolved);
    const completedTargets:Target[]=overrides.map((a,overrideIndex)=>({action:a.annotation.action,location:a.location,selector:a.annotation.selector,overrideIndex}));
    const candidates=[...pendingTargets,...completedTargets].filter(t=>(buffer.writable || t.selector) && t.location.path===buffer.path && t.location.available && t.location.hash===buffer.hash).map(t=>{
      const position=editorPosition(buffer.content,t.location.start);
      const added=t.overrideIndex===undefined?undefined:overrides[t.overrideIndex];
      const widget=new DocumentationPrompt(t.action,()=>{
        documentationRef.current(t);
      },!!t.selector,added?'Override saved':'');
      const candidate={position,action:t.action,external:!!t.selector,widget};
      if(!candidate.external&&candidate.action==='justification'&&!sourcePromptAttachments(view.state.doc.toString(),[candidate])[0].insertable)manualTargets.current.actions.add(candidate.action);
      return {...candidate,manual:manualTargets.current.actions.has(candidate.action)};
    });
    type Candidate = typeof candidates[number];
    function decorate(state:EditorState, candidates:Candidate[]) {
      if(!enabled)return Decoration.none;
      const attachments=sourcePromptAttachments(state.doc.toString(),candidates,finding?.audit);
      const resolved=attachments.some(a=>a.attached);
      return Decoration.set(candidates.flatMap((candidate,index)=>{
        const attachment=attachments[index];
        if(!candidate.external && ((!attachment.attached&&resolved) || (candidate.manual&&attachment.attached)))return [];
        const manual=!candidate.external&&candidate.action==='justification'&&!attachment.insertable;
        if(!candidate.external&&!attachment.insertable&&!manual)return [];
        const widget=!candidate.external&&attachment.attached
          ?new DocumentationPrompt(candidate.action,candidate.widget.run,false,'Saved in source')
          :manual?new DocumentationPrompt(candidate.action,()=>{
            view?.dispatch({selection:{anchor:candidate.position},effects:EditorView.scrollIntoView(candidate.position)});
            setManualMarker(finding?.audit?.justification.trim().replace(/:$/, '')||'');
          },false,'',true):candidate.widget;
        return [Decoration.widget({widget,block:true,side:-1}).range(attachment.markerStart??attachment.lineStart)];
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
  },[buffer.path,buffer.revision,finding?.id,finding?.audit?.targets,enabled,reloadKey,hideDocumentation,trustPrompt]);
  useEffect(()=>{
    const view=editorRef.current;
    if(!view || !target?.available || target.path!==buffer.path)return;
    const source=view.state.sliceDoc();
    const from=editorPosition(source,target.start),to=editorPosition(source,target.end);
    if(from<=to && to<=view.state.doc.length){view.dispatch({selection:{anchor:from,head:to},effects:EditorView.scrollIntoView(from,{y:'center'})});view.focus();}
  },[target,buffer.path,reloadKey]);
  return <><div className="editor" ref={holder} aria-label="Rust source editor"/>
    {manualMarker!==undefined&&<DocumentationPanel source title="Needs manual justification" step="manual" onClose={closeManualGuidance}>
      {finding?.audit?.obligation_documentation&&<ObligationDocumentationPanel documentation={finding.audit.obligation_documentation}/>}
      {!finding?.audit?.obligation_documentation&&finding?.audit?.effect_context&&<p className="effect-class-label" aria-label="Effect class">{effectContextLabel(finding.audit.effect_context)}</p>}
      <PopupProducer key={finding?.id} finding={finding} navigation={navigation}/>
      <p>Add a <code>// {manualMarker}:</code> justification comment manually above this effect.</p>
      <div className="modal-actions"><button autoFocus onClick={closeManualGuidance}>Close</button></div>
    </DocumentationPanel>}
  </>;
}
function placeCaretAtEnd(element:HTMLTextAreaElement|null) {
  if(element)element.setSelectionRange(element.value.length,element.value.length);
}
function DocumentationPanel({title,children,onClose,step,source=false}:{title:string;children:React.ReactNode;onClose:()=>void;step:string;source?:boolean}) {
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
      <div className="override-drag-handle" role="button" tabIndex={0} aria-label={source?'Move documentation popup':'Move override popup'} title="Drag to move; use arrow keys when focused"
        onPointerDown={e=>{if(e.button!==0)return;e.preventDefault();e.currentTarget.focus();e.currentTarget.setPointerCapture(e.pointerId);const bounds=ref.current!.getBoundingClientRect();drag.current={x:e.clientX,y:e.clientY,left:bounds.left,top:bounds.top};}}
        onPointerMove={e=>{if(drag.current)place(drag.current.left+e.clientX-drag.current.x,drag.current.top+e.clientY-drag.current.y);}}
        onPointerUp={e=>{drag.current=undefined;e.currentTarget.releasePointerCapture(e.pointerId);}}
        onPointerCancel={()=>{drag.current=undefined;}} onLostPointerCapture={()=>{drag.current=undefined;}}
        onKeyDown={e=>{const dx=e.key==='ArrowLeft'?-20:e.key==='ArrowRight'?20:0,dy=e.key==='ArrowUp'?-20:e.key==='ArrowDown'?20:0;if((dx||dy)&&position.current){e.preventDefault();place(position.current.left+dx,position.current.top+dy);}}}
      ><h2>{title}</h2><span aria-hidden="true">⠿</span></div>
      <button type="button" aria-label={source?'Close documentation popup':'Close override popup'} onClick={onClose}>×</button>
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
  const [trustReview,setTrustReview]=useState<Obligation>();
  const [confirmUntrust,setConfirmUntrust]=useState(false);
  const [leftWidth,setLeftWidth]=useState(285),[rightWidth,setRightWidth]=useState(315);
  const [root,setRoot]=useState(''); const [status,setStatus]=useState<Status>({generation:0,running:false,stale:true,status:'connecting',count:0,log:''});
  const [groups,setGroups]=useState<FindingGroup[]>([]),[total,setTotal]=useState(0),[totalGroups,setTotalGroups]=useState(0),[effects,setEffects]=useState<string[]>([]);
  const [mode,setMode]=useState<DisplayMode>('file');
  const inverted=mode==='effect-source',obligationMode=mode==='obligation';
  const [granularity,setGranularity]=useState<'origin'|'crate'>('origin');
  const crateMode=inverted&&granularity==='crate';
  const modeIndex=mode==='file'?0:inverted?(crateMode?3:1):2;
  const [crateExpanded,setCrateExpanded]=useState<Set<string>>(()=>new Set());
  const [crateReview,setCrateReview]=useState<CrateTrust>();
  const [crateEffects,setCrateEffects]=useState<string[]>([]);
  const [obligation,setObligation]=useState<Obligation>();
  const [obligationSource,setObligationSource]=useState(false);
  const [expanded,setExpanded]=useState<Set<string>>(()=>new Set());
  const [obligationExpanded,setObligationExpanded]=useState<Set<string>>(()=>new Set());
  const [sourceExpanded,setSourceExpanded]=useState<Set<string>>(()=>new Set());
  const [query,setQuery]=useState(''),[effect,setEffect]=useState(''),[level,setLevel]=useState(''),[kind,setKind]=useState('');
  const [pages,setPages]=useState([0,0,0,0]);
  const page=pages[modeIndex];
  function setPage(value:number|((page:number)=>number)){listScroll.current[modeIndex]=0;setPages(previous=>previous.map((p,i)=>i===modeIndex?typeof value==='function'?value(p):value:p));}
  function resetPages(){setPages([0,0,0,0]);listScroll.current=[0,0,0,0];}
  const listElement=useRef<HTMLDivElement>(null),listScroll=useRef([0,0,0,0]);
  const listCache=useRef(new Map<string,{groups:FindingGroup[];total:number;total_groups:number;effects:string[]}>());
  const rowCache=useRef(new Map<string,Summary[]>());
  const rowReads=useRef(new Map<string,AbortController>());
  const [listLoading,setListLoading]=useState(false),[listFailure,setListFailure]=useState(''),[listRetry,setListRetry]=useState(0);
  const [listResult,setListResult]=useState(''),[listResultView,setListResultView]=useState('');
  const groupsRef=useRef(groups);groupsRef.current=groups;
  const listRevision=JSON.stringify([status.results_revision,status.generation,status.running,status.audit_revision,status.override_revision]);
  const listFilter=JSON.stringify([query,effect,level,obligationMode?'':kind,mode,crateMode?'crate':'origin']);
  // Metadata saves refresh the same view; only a different dataset or query hides its rows.
  const listView=JSON.stringify([status.results_revision,status.generation,listFilter,page]);
  const listKey=JSON.stringify([listRevision,listFilter,page]);
  const listVisible=listResultView===listView;
  const activeList=useRef(listKey);activeList.current=listKey;
  const filters=()=>({q:query,effect,level,class:obligationMode?'':kind,grouped:'true',group_by:mode,granularity:crateMode?'crate':'origin'});
  function cacheRows(key:string,rows:Summary[]){rowCache.current.delete(key);rowCache.current.set(key,rows);if(rowCache.current.size>32)rowCache.current.delete(rowCache.current.keys().next().value!);}
  function rowsKey(key:string){return JSON.stringify([listRevision,listFilter,key]);}
  const [selected,setSelected]=useState<Finding>(),[buffer,setBuffer]=useState<Buffer>(),[text,setText]=useState(''),[target,setTarget]=useState<Location>();
  const inspectingObligation=obligationMode&&!selected;
  const [saveState,setSaveState]=useState<SaveState>({status:'saved'}),[reloadKey,setReloadKey]=useState(0),[startingAnalysis,setStartingAnalysis]=useState(false),[opening,setOpening]=useState(false);
  const [error,setError]=useState(''),[busy,setBusy]=useState(false);
  const [nav,setNav]=useState<Location[]>([]);
  const [documentationEditor,setDocumentationEditor]=useState<DocumentationEditor>();
  const [confirmRemoval,setConfirmRemoval]=useState(false);
  const [createFile,setCreateFile]=useState(false),[overrideFilename,setOverrideFilename]=useState('sniff-test-overrides.toml');
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
  function changeSource(content:string,changes:ChangeDesc,previous:string,acknowledged=false,path=saver.current!.snapshot?.path){
    setNav(history=>history.map(loc=>{
      if(loc.path!==path || !loc.live)return loc;
      const from=changes.mapPos(editorPosition(previous,loc.start),1);
      const to=Math.max(from,changes.mapPos(editorPosition(previous,loc.end),-1));
      return {...loc,start:sourceBytePosition(content,from),end:sourceBytePosition(content,to)};
    }));
    if(path===saver.current!.snapshot?.path){setText(content);if(!acknowledged)saver.current!.change(content);}
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
  const acknowledgeSource=useRef<((saved:SavedSource)=>void)|undefined>(undefined);
  const documentationOrigin=useRef<{view:EditorView;sequence:number}|undefined>(undefined);
  const restoreDocumentationFocus=useRef(false);
  useLayoutEffect(()=>{
    if(documentationEditor || !restoreDocumentationFocus.current)return;
    restoreDocumentationFocus.current=false;
    const origin=documentationOrigin.current;
    if(origin && origin.view===editor.current && origin.sequence===openSequence.current)origin.view.focus();
  },[documentationEditor]);
  const waitingEditor=useRef<{path:string;resolve:(view:EditorView|null)=>void}|undefined>(undefined);
  function editorReady(view:EditorView|undefined,acknowledge?: (saved:SavedSource)=>void){editor.current=view;acknowledgeSource.current=acknowledge;if(view && waitingEditor.current && waitingEditor.current.path===buffer?.path){waitingEditor.current.resolve(view);waitingEditor.current=undefined;}}
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
  useLayoutEffect(()=>{detailsScroll.current?.scrollTo({top:0});},[selected?.id,obligation?.key,mode]);
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
  async function changeMode(next:DisplayMode){
    await saver.current!.flush();
    if(listElement.current)listScroll.current[modeIndex]=listElement.current.scrollTop;
    if(next==='obligation'||obligationMode){startNavigation();setOpening(false);setSelected(undefined);setObligation(undefined);setDocumentationEditor(undefined);}
    setMode(next);
  }
  async function chooseObligation(group:FindingGroup){
    const sequence=startNavigation();
    try{
      await saver.current!.flush();if(sequence!==openSequence.current)return;
      const detail:Obligation=await api('obligation?'+new URLSearchParams({key:group.key}),undefined,navigationRead.current?.signal);
      if(sequence!==openSequence.current)return;
      setSelected(undefined);setObligationSource(false);
      if(detail.declaration?.available){
        try{
          const opened=await open(detail.declaration,true,sequence);
          if(sequence!==openSequence.current)return;
          setObligationSource(opened&&!!detail.declaration.hash&&saver.current!.snapshot?.hash===detail.declaration.hash);
        }catch(e){if(sequence!==openSequence.current)return;setError(String(e));}
      }
      setObligation({...detail,count:group.count});
    }catch(e){if(sequence===openSequence.current)throw e;}
    finally{if(sequence===openSequence.current)setOpening(false);}
  }
  async function trustObligation(remove=false){
    const obligation=trustReview;
    if(!obligation)return;
    await saver.current!.flush();
    const result=await api(remove?'obligation/untrust':'obligation/trust',{key:obligation.key,results_revision:obligation.results_revision,config_hash:obligation.config_hash??null});
    setObligation(current=>current&&current.key===result.obligation.key?{...result.obligation,count:current.count}:current);
    setGroups(groups=>groups.map(group=>group.key===result.obligation.key?{...group,trusted:result.obligation.trusted}:group));
    setTrustReview(undefined);
    setConfirmUntrust(false);
    acceptStatus(result.status);
  }
  async function reviewCrate(group:FindingGroup){
    const detail:CrateTrust=await api('crate/trust?'+new URLSearchParams({crate_name:group.crate_name!}));
    setCrateReview(detail);
    setCrateEffects(Object.keys(group.effects||{}).filter(e=>!effect||e===effect));
    setError('');
  }
  async function saveCrateTrust(remove=false){
    if(!crateReview)return;
    await saver.current!.flush();
    const result=await api(remove?'crate/untrust':'crate/trust',{crate_name:crateReview.crate_name,effects:crateEffects,results_revision:crateReview.results_revision,config_hash:crateReview.config_hash??null});
    setGroups(previous=>previous.map(group=>group.crate_name===result.crate.crate_name?{...group,trusted:Object.keys(group.effects||{}).every(effect=>result.crate.effects.some((entry:CrateTrust['effects'][number])=>entry.effect===effect&&entry.trusted))}:group));
    setCrateReview(undefined);
    acceptStatus(result.status);
  }
  async function choose(item:Summary,sourceOnly=false){
    const sequence=startNavigation();
    try {
      await saver.current!.flush();if(sequence!==openSequence.current)return;
      const finding:Finding=await api('finding?'+new URLSearchParams({id:item.id}),undefined,navigationRead.current?.signal);
      if(sequence!==openSequence.current)return;
      const location=(sourceOnly?[destination(finding,'source')]:[destination(finding,'source'),destination(finding,'root')]).find(value=>value?.available);
      if(sourceOnly&&!location)throw Error('Source is unavailable for this origin.');
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
      setGroups(value.groups.map(group=>{
        const cachedRows=rowCache.current.get(rowsKey(group.key))||group.items;
        const previous=listVisible?groupsRef.current.find(previous=>previous.key===group.key):undefined;
        return {...group,items:cachedRows||previous?.items,rowsRevision:cachedRows?listRevision:previous?.rowsRevision};
      }));
      setTotal(value.total);setTotalGroups(value.total_groups);setEffects(value.effects);setListResultView(listView);setListResult(listKey);setListLoading(false);
    }
    if(cached){display(cached);return;}
    setListLoading(true);
    api('findings?'+new URLSearchParams({...filters(),headers_only:'true',offset:String(page*100)}),undefined,controller.signal).then(value=>{
      if(controller.signal.aborted)return;
      listCache.current.set(listKey,value);
      if(listCache.current.size>16)listCache.current.delete(listCache.current.keys().next().value!);
      display(value);
    }).catch(e=>{if(!controller.signal.aborted&&activeList.current===listKey){if(!listVisible){setGroups([]);setTotal(0);setTotalGroups(0);}else setGroups(previous=>previous.map(group=>({...group,loading:false})));setListResultView(listView);setListResult(listKey);setListFailure(String(e));setListLoading(false);}});
    return ()=>controller.abort();
  },[listKey,listRetry]);
  useLayoutEffect(()=>{
    if(listVisible&&listElement.current)listElement.current.scrollTop=listScroll.current[modeIndex];
  },[listView,listResultView,groups]);
  useEffect(()=>()=>{for(const controller of rowReads.current.values())controller.abort();rowReads.current.clear();},[listKey]);
  async function loadRows(key:string,more=false){
    const requestKey=listKey,cacheKey=rowsKey(key);
    const current=groups.find(g=>g.key===key);
    if(!current||current.loading||rowReads.current.has(key)||listResult!==listKey)return;
    const controller=new AbortController();rowReads.current.set(key,controller);
    const existing=more?(current.items||[]):[];
    setGroups(previous=>previous.map(g=>g.key===key?{...g,loading:true,loadError:undefined}:g));
    try{
      const items=[...existing];
      const target=more?existing.length+100:Math.max(100,current.items?.length||0);
      do {
        const value=await api('group-items?'+new URLSearchParams({...filters(),group_key:key,offset:String(items.length),limit:String(Math.min(100,target-items.length))}),undefined,controller.signal);
        if(activeList.current!==requestKey)return;
        items.push(...value.items);
        if(!value.items.length||items.length>=value.total)break;
      } while(items.length<target);
      cacheRows(cacheKey,items);
      setGroups(previous=>previous.map(g=>g.key===key?{...g,items,rowsRevision:listRevision,loading:false}:g));
    }catch(e){if(!controller.signal.aborted&&activeList.current===requestKey)setGroups(previous=>previous.map(g=>g.key===key?{...g,loading:false,loadError:String(e)}:g));}
    finally{if(rowReads.current.get(key)===controller)rowReads.current.delete(key);}
  }
  useEffect(()=>{
    if(listResult!==listKey||listFailure)return;
    const open=obligationMode?obligationExpanded:crateMode?crateExpanded:inverted?sourceExpanded:expanded;
    for(const group of groups)if(open.has(group.key)&&(!group.items||group.rowsRevision!==listRevision)&&!group.loading&&!group.loadError)void loadRows(group.key);
  },[groups,expanded,sourceExpanded,crateExpanded,obligationExpanded,listResult,listKey,listFailure]);
  useEffect(()=>{openSequence.current++;navigationRead.current?.abort();setOpening(false);setSelected(undefined);setObligation(undefined);},[status.generation,status.results_revision]);
  useEffect(()=>{const warn=(e:BeforeUnloadEvent)=>{if(saver.current?.pending||documentationEditor){e.preventDefault();}};window.addEventListener('beforeunload',warn);return()=>window.removeEventListener('beforeunload',warn)},[unsaved,documentationEditor]);
  async function openDocumentation(t:Target) {
    if(documentationEditor){document.querySelector<HTMLElement>('.override-drag-handle')?.focus();return;}
    if(!buffer)return;
    documentationOrigin.current=editor.current?{view:editor.current,sequence:openSequence.current}:undefined;
    if(!t.selector){
      const finding=selectedRef.current;if(!finding)throw Error('Select a finding before editing documentation.');
      await saver.current!.flush();
      if(selectedRef.current?.id!==finding.id)throw Error('The selected finding changed. Try again.');
      const snapshot=saver.current!.snapshot!;
      const context=await api('source/editor',{id:finding.id,action:t.action,revision:snapshot.revision,generation:status.generation});
      setCreateFile(false);setConfirmRemoval(false);
      setDocumentationEditor({...context,producerFinding:selectedRef.current?.id===finding.id?selectedRef.current:undefined,mode:'source',finding:finding.id,action:t.action,saved_destination:context.destination,destinations:[]});
      return;
    }
    const annotation=t.overrideIndex===undefined?undefined:buffer.saved_overrides[t.overrideIndex];
    if(!annotation&&!selected)throw Error('Select a finding before adding an override.');
    const producerFinding=(!annotation || selected?.audit?.targets.some(target=>target.action===t.action&&sameSelector(target.selector,t.selector)))?selected:undefined;
    const request=annotation?{path:buffer.path,index:t.overrideIndex,revision:buffer.revision}:{id:selected?.id,action:t.action,revision:buffer.revision,generation:status.generation};
    const context=await api('override/editor',request);
    setCreateFile(false);setOverrideFilename('sniff-test-overrides.toml');
    setConfirmRemoval(false);
    setDocumentationEditor({...context,producerFinding:selectedRef.current?.id===producerFinding?.id?producerFinding:undefined,mode:'override',saved_destination:context.destination,action:t.action});
  }
  async function commitDocumentation(filename?:string) {
    if(!documentationEditor)return;
    if(documentationEditor.mode==='source'){await saveSourceAnnotation(false);return;}
    const result=await api('override/commit',{token:documentationEditor.token,destination:documentationEditor.destination,document:documentationEditor.document,filename});
    if(saver.current!.snapshot?.path===result.buffer.path){saver.current!.load(result.buffer);setBuffer(result.buffer);setText(result.buffer.content);}
    acceptStatus(result.status);restoreDocumentationFocus.current=true;
    setCreateFile(false);setDocumentationEditor(undefined);
  }

  async function removeDocumentation() {
    if(!documentationEditor)return;
    if(documentationEditor.mode==='source'){await saveSourceAnnotation(true);return;}
    const result=await api('override/remove',{token:documentationEditor.token});
    if(saver.current!.snapshot?.path===result.buffer.path){saver.current!.load(result.buffer);setBuffer(result.buffer);setText(result.buffer.content);}
    acceptStatus(result.status);restoreDocumentationFocus.current=true;
    setConfirmRemoval(false);setDocumentationEditor(undefined);
  }

  async function saveSourceAnnotation(remove:boolean) {
    if(!documentationEditor)return;
    await saver.current!.flush();
    const result=await api(remove?'source/remove':'source/commit',{token:documentationEditor.token,document:documentationEditor.document,finding:documentationEditor.finding});
    if(saver.current!.snapshot?.path===result.buffer.path){saver.current!.load(result.buffer);setBuffer(result.buffer);setText(result.buffer.content);}
    acknowledgeSource.current?.(result);
    navigation?.document(result.buffer.path,result.buffer.content);acceptStatus(result.status);
    restoreDocumentationFocus.current=true;
    setSelected(current=>current&&current.id===result.finding?{...current,navigation:result.navigation,audit:current.audit?{...current.audit,targets:result.targets}:undefined}:current);
    setConfirmRemoval(false);setDocumentationEditor(undefined);
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
      <label className="display-mode"><strong>Display mode:</strong>
        <select aria-label="Display mode" value={mode} disabled={!!documentationEditor} onChange={e=>{const next=e.target.value as DisplayMode;act(()=>changeMode(next));}}>
          <option value="file">File</option>
          <option value="effect-source">Effect</option>
          <option value="obligation">Obligation</option>
        </select>
      </label>
      {inverted&&<label className="display-mode"><strong>Granularity:</strong><select aria-label="Granularity" value={granularity} disabled={!!documentationEditor} onChange={e=>setGranularity(e.target.value as 'origin'|'crate')}><option value="origin">Origin</option><option value="crate">Crate</option></select></label>}
      <input aria-label={obligationMode?'Search obligations':inverted?'Search effect sources':'Search findings'} placeholder={obligationMode?'Search functions, obligations…':inverted?(crateMode?'Search crates or origins…':'Search effect sources…'):'Search files, roots, crates…'} value={query} onChange={e=>{setQuery(e.target.value);resetPages();}}/>
      <div className="filters"><select aria-label="Effect" value={effect} onChange={e=>{setEffect(e.target.value);resetPages();}}><option value="">All effects</option>{effects.map(e=><option key={e}>{e}</option>)}</select><select aria-label="Severity" value={level} onChange={e=>{setLevel(e.target.value);resetPages();}}><option value="">All levels</option><option>warn</option><option>deny</option></select></div>
      {!obligationMode&&<select aria-label="Finding class" value={kind} onChange={e=>{setKind(e.target.value);resetPages();}}><option value="">All finding classes</option>{['concrete-operation','concrete-invocation','documented-obligation','undocumented-invocation','unresolved-call-target','analysis-incomplete','ambiguous-marker','ambiguous-requirement'].map(k=><option key={k}>{k}</option>)}</select>}
      <div className={'finding-list'+(listVisible&&groups.length?' has-rows':'')} ref={listElement} aria-busy={listLoading||listResult!==listKey} onScroll={e=>{if(listVisible)listScroll.current[modeIndex]=e.currentTarget.scrollTop;}}>{!listVisible&&(listLoading||listResult!==listKey)&&<div className="loading" role="status">Loading {obligationMode?'obligations':inverted?'effect sources':'files'}…</div>}{(listVisible?groups:[]).map(({key, label,path:sourcePath,items:rows,count,progress,trusted,loading,loadError,crate_name,item_count,effects:groupEffects},index)=>{
        const path=label||key;
        if(crateMode){
          const isOpen=crateExpanded.has(key),listId=`crate-origins-${index}`,originCount=item_count||0;
          return <section key={key} className="crate-section">
            <div className="crate-header"><button type="button" className="group" title={label} aria-expanded={isOpen} aria-controls={listId} onClick={()=>setCrateExpanded(previous=>{const next=new Set(previous);if(next.has(key))next.delete(key);else next.add(key);return next;})}><span className="group-chevron" aria-hidden="true">{isOpen?'▾':'▸'}</span><span className="group-path">{label}</span>{trusted&&<span className="audit-progress"><span role="img" aria-label="Crate trusted" title="Crate trusted for all displayed effects; reanalyze to update findings">✓</span></span>}<AuditMarks progress={progress} group/><span className="group-count" aria-label={`${count} reports`}>{count}</span></button>
              {crate_name&&<button className={'crate-trust'+(trusted?' completed':'')} disabled={busy||status.running||startingAnalysis} aria-label={`${trusted?'Trusted':'Trust'} ${crate_name}`} onClick={()=>act(()=>reviewCrate({key,count,crate_name,effects:groupEffects}))}>{trusted?'✓ Trusted':'Trust'}</button>}
            </div>
            <div id={listId} hidden={!isOpen}>{isOpen&&(rows||[]).map(item=><button type="button" className={'finding crate-origin '+(selected?.id===item.id?'selected':'')} title={item.label} key={item.id} onClick={()=>act(()=>choose(item,true))}><span className="finding-label"><span className="badge">{item.effect||item.class}</span><AuditMarks progress={item.progress} group/><span className="group-count" aria-label={`${item.count} reports`}>{item.count}</span></span><strong>{item.description}</strong><small>{item.path?item.location_label?.replace(item.path,()=>displaySourcePath(item.path!,root)):item.location_label}</small></button>)}
              {isOpen&&loading&&<div className={rows?.length?'refresh-status':'loading'} role="status">Loading origins…</div>}
              {isOpen&&loadError&&<div role="alert">{loadError}<button onClick={()=>void loadRows(key)}>Retry</button></div>}
              {isOpen&&rows&&rows.length<originCount&&<button className="load-more" disabled={loading} onClick={()=>void loadRows(key,true)}>Load more ({rows.length} of {originCount} origins)</button>}
            </div>
          </section>;
        }
        const openGroups=obligationMode?obligationExpanded:inverted?sourceExpanded:expanded;
        const setOpenGroups=obligationMode?setObligationExpanded:inverted?setSourceExpanded:setExpanded;
        const isOpen=openGroups.has(key),listId=`${obligationMode?'obligation':inverted?'source':'file'}-findings-${index}`;
        return <section key={key}><button type="button" className={'group'+(obligationMode?' obligation-row':'')+(obligationMode&&!selected&&obligation?.key===key?' selected':'')} title={path} aria-expanded={isOpen} aria-controls={listId} onClick={()=>{
          setOpenGroups(previous=>{const next=new Set(previous);if(next.has(key))next.delete(key);else next.add(key);return next;});
          if(obligationMode)act(()=>chooseObligation({key,label,count}));
        }}><span className="group-chevron" aria-hidden="true">{isOpen?'▾':'▸'}</span><span className="group-path">{sourcePath?path.replace(sourcePath,()=>displaySourcePath(sourcePath,root)):displaySourcePath(path,root)}</span>{obligationMode&&trusted&&<span className="audit-progress obligation-trust"><span role="img" aria-label="Obligations ignored" title="Ignore saved; reanalyze to update findings">✓</span></span>}<AuditMarks progress={progress} group/><span className="group-count" aria-label={`${count} ${inverted||obligationMode?'reports':'effects'}`} >{count}</span></button><div id={listId} hidden={!isOpen}>{isOpen&&(rows||[]).map(item=><button className={'finding '+(selected?.id===item.id?'selected':'')} key={item.id} onClick={()=>act(()=>choose(item))}><span className="finding-label"><span className="badge">{item.effect||item.class}</span><AuditMarks progress={item.progress}/></span><strong>{item.root||item.crate_name}</strong><small>{item.reason}</small></button>)}{isOpen&&loading&&<div className={rows?.length?'refresh-status':'loading'} role="status">Loading findings…</div>}{isOpen&&loadError&&<div role="alert">{loadError}<button onClick={()=>void loadRows(key)}>Retry</button></div>}{isOpen&&rows&&rows.length<count&&<button className="load-more" disabled={loading} onClick={()=>void loadRows(key,true)}>Load more ({rows.length} of {count})</button>}</div></section>;
      })}{listResult===listKey&&listFailure&&<div className="list-refresh-error" role="alert">{listFailure}<button onClick={()=>setListRetry(value=>value+1)}>Retry findings</button></div>}{listResult===listKey&&!listLoading&&!listFailure&&!groups.length&&<div className="empty">{status.running?'Analyzing the workspace…':status.status==='complete'?'No matching findings.':'No findings available. Check analysis output.'}</div>}</div>
      <div className="pagination"><button aria-label={obligationMode?'Previous obligations':inverted?(crateMode?'Previous crates':'Previous effect sources'):'Previous files'} disabled={page===0} onClick={()=>setPage(p=>p-1)}>←</button><span>{obligationMode?'Obligations':inverted?(crateMode?'Crates':'Effect sources'):'Files'} · {page+1} / {Math.max(1,Math.ceil(totalGroups/100))}</span><button aria-label={obligationMode?'Next obligations':inverted?(crateMode?'Next crates':'Next effect sources'):'Next files'} disabled={(page+1)*100>=totalGroups} onClick={()=>setPage(p=>p+1)}>→</button></div>
    </aside><PanelDivider side="left" size={leftWidth} onResize={setLeftWidth}/></div>
    <main aria-busy={opening}><div className="toolbar"><button disabled={!nav.length||busy} onClick={()=>act(async()=>{const previous=nav[nav.length-1];if(await open(previous,false))setNav(n=>n.slice(0,-1));})}>← Back</button><span className="filename" title={buffer?.path}>{buffer?displaySourcePath(buffer.path,root):'Source workspace'}</span>{opening&&<span className="navigation-loading" role="status">Opening source…</span>}{buffer?.writable&&<span className="save-status" role="status" aria-label="Source save status">{saveState.status==='failed'?'Save failed':saveState.status==='saving'?'Saving…':saveState.status==='pending'?'Unsaved changes':'Saved'}</span>}</div>
      {saveState.status==='failed'&&<div className="error source-save-error" role="alert"><span>{saveState.error}</span><button disabled={busy} onClick={()=>act(()=>saver.current!.retry())}>Retry</button><button disabled={busy} onClick={()=>act(()=>navigator.clipboard.writeText(saver.current!.text))}>Copy edits</button><button disabled={busy} onClick={()=>act(reloadSource)}>Reload file</button></div>}
      {inspectingObligation&&!obligationSource?<div className="obligation-fallback">{obligation?<><h2>{obligation.namespace}</h2>{obligation.documentation?<ObligationDocumentationPanel documentation={obligation.documentation}/>:<p>Obligation documentation is unavailable.</p>}<p>Verified function source is unavailable.</p><div className="inline-prompt"><button className={obligation.trusted?'completed':''} aria-label={obligation.trusted?'Ignored':'Ignore Obligations'} disabled={busy||status.running||startingAnalysis} onClick={()=>{setError('');setConfirmUntrust(false);setTrustReview(obligation);}}>✓ {obligation.trusted?'Ignored':'Ignore Obligations'}</button><span>Ignore this function’s obligations for {obligation.effect}.</span></div></>:null}</div>:buffer?<><div className="buffer-state"><span className="navigation-status">{navigationStatus}</span>{buffer.writable?'Workspace source':'Read-only dependency'}{(status.running||startingAnalysis)&&buffer.writable?' · Editing paused during analysis':''}</div>
      <Editor hideDocumentation={inspectingObligation} trustPrompt={inspectingObligation&&obligation?.declaration?{location:obligation.declaration,trusted:obligation.trusted,run:()=>{setError('');setConfirmUntrust(false);setTrustReview(obligation);}}:undefined} locked={inspectingObligation||status.running||startingAnalysis||documentationEditor?.mode==='source'} reloadKey={reloadKey} onFlush={flushSource} navigation={navigation} onReady={editorReady} buffer={buffer} location={target} onChange={changeSource} onSelectionChange={setEditorSelection} finding={selected} enabled={!status.running&&!startingAnalysis&&(!inspectingObligation||!busy)} onDocumentation={t=>act(()=>openDocumentation(t))}/></>:null}

    </main>
    <div className="side-pane right-pane" id="details-panel"><PanelDivider side="right" size={rightWidth} onResize={setRightWidth}/><aside className="details" aria-label="Effect details">{inspectingObligation?obligation?<section className="effect-summary" aria-label="Selected obligation"><div className="section-title">OBLIGATION DETAILS</div><p>{obligation.namespace}</p><p>{obligation.effect} · {obligation.count} reports</p><p>{obligation.trusted?'Ignored · reanalyze to update findings':'Ignore this function’s obligations for this effect by adding it to ignored-namespaces.'}</p><small>{obligation.config_path}</small></section>:<div className="empty">Select an obligation to inspect its documentation.</div>:selected?<><section className="effect-summary" aria-label="Selected effect"><div className="section-title">FINDING DETAILS</div><p>{selected.reason}</p><small>{selected.crate_name} · trace {selected.trace_id||'unavailable'}</small></section>
      <div className="details-scroll" ref={detailsScroll} tabIndex={0} aria-label="Navigation and call trace"><h3>Navigate</h3>{[['Report root','root'],['Effect source','source'],['Contract','contract']].map(([label,kind])=><button className="link" key={label} disabled={!destination(selected,kind as 'source'|'root'|'contract')?.available} onClick={()=>act(()=>navigateFinding(kind as 'source'|'root'|'contract'))}>{label}{!destination(selected,kind as 'source'|'root'|'contract')?.available?' · unavailable':''}</button>)}
      {selected.audit&&!selected.audit.targets.length&&<p className="hint">No verified documentation attachment location is available. Inspect the source and edit manually where appropriate.</p>}
      {status.override_error?<p className="hint" role="alert">{status.override_error}</p>:null}
      {target?.approximate?<p className="hint" role="status">Approximate location; reanalyze to refresh.</p>:null}
      {unsaved||status.stale?<p className="hint">Findings are outdated. Reanalyze to refresh them.</p>:null}
      <h3>Call trace</h3><ol className="trace" reversed={inverted}>{traceEntries.map(({step,i})=><li key={i} value={i+1}><button className={highlightedTraceIndex===i?'active':''} aria-current={highlightedTraceIndex===i?'location':undefined} disabled={!step.location?.available} onClick={()=>act(()=>navigateFinding(i))}>{step.caller}<span>{step.kind} → {step.target||'effect operation'}</span><small title={step.location?.path}>{!step.location?'':displaySourcePath(step.location.path,root)}{step.location?.line?':'+step.location.line:''}{!step.location?.available?' · source unavailable':step.location.approximate?' · approximate':''}</small></button></li>)}</ol></div>
    </>:<div className="empty">Select a finding to inspect its contract and call trace.</div>}</aside></div></div>
    {crateReview&&<DocumentationPanel source title="Crate trust" step="review" onClose={()=>{if(!busy)setCrateReview(undefined);}}>
      {error&&<p role="alert">{error}</p>}
      <p>Namespace: <code>{crateReview.namespace}</code></p>
      <fieldset className="crate-effects" disabled={busy||status.running||startingAnalysis}><legend>Effects</legend>{crateReview.effects.map(entry=><label key={entry.effect}><input type="checkbox" checked={crateEffects.includes(entry.effect)} onChange={event=>setCrateEffects(previous=>event.target.checked?[...previous,entry.effect]:previous.filter(e=>e!==entry.effect))}/><span>{entry.effect}{entry.trusted?' · Trusted':''}</span><small>{entry.count} reports</small></label>)}</fieldset>
      <p>Override file: <code>{displaySourcePath(crateReview.config_path,root)}</code></p>
      <div className="modal-actions"><button disabled={busy} onClick={()=>setCrateReview(undefined)}>Close</button><button disabled={busy||status.running||startingAnalysis||!crateEffects.length||!crateEffects.every(effect=>crateReview.effects.some(e=>e.effect===effect&&e.exact))} onClick={()=>act(()=>saveCrateTrust(true))}>Remove</button><button className="primary" disabled={busy||status.running||startingAnalysis||!crateEffects.length||crateEffects.every(effect=>crateReview.effects.some(e=>e.effect===effect&&e.trusted))} onClick={()=>act(()=>saveCrateTrust())}>Trust</button></div>
    </DocumentationPanel>}
    {trustReview&&<DocumentationPanel source title="Obligation ignore" step={confirmUntrust?'remove':'review'} onClose={()=>{if(!busy)setTrustReview(undefined);}}>
      {error&&<p role="alert">{error}</p>}
      {trustReview.documentation?<ObligationDocumentationPanel documentation={trustReview.documentation}/>:<p>Obligation documentation is unavailable.</p>}
      {!trustReview.documentation?.prototype&&<p>Function prototype is unavailable.</p>}
      {confirmUntrust?<>
        <p>Stop ignoring obligations for <strong>{trustReview.namespace}</strong> for {trustReview.effect} by removing its entry from ignored-namespaces? Reanalyze to update findings.</p>
        <div className="modal-actions"><button disabled={busy} onClick={()=>setConfirmUntrust(false)}>Cancel</button><button disabled={busy||status.running||startingAnalysis} onClick={()=>act(()=>trustObligation(true))}>Confirm removal</button></div>
      </>:<>
        <div className="modal-actions"><button disabled={busy} onClick={()=>setTrustReview(undefined)}>Close</button><button className={trustReview.trusted?undefined:'primary'} disabled={busy||status.running||startingAnalysis} onClick={()=>trustReview.trusted?setConfirmUntrust(true):void act(()=>trustObligation())}>{trustReview.trusted?'Cancel ignore':'Ignore Obligations'}</button></div>
      </>}
    </DocumentationPanel>}
    {documentationEditor&&<DocumentationPanel source={documentationEditor.mode==='source'} title={createFile?'Create override file':documentationEditor.mode==='source'?(documentationEditor.action==='justification'?'Justify here':'Propagate to callers'):documentationEditor.action==='justification'?'Justify via override':'Propagate obligations via override'} step={createFile?'create':confirmRemoval?'remove':'edit'} onClose={()=>{if(!busy){if(createFile)setCreateFile(false);else setDocumentationEditor(undefined);}}}>
      {!createFile?<>
      {error&&<p role="alert">{error}</p>}
      {confirmRemoval?<>
        <p className="override-removal">Remove this saved {documentationEditor.mode==='source'?(documentationEditor.action==='justification'?'justification':'obligation'):'override'} from <strong>{displaySourcePath(documentationEditor.saved_destination,root)}</strong>?</p>
        <p>Only this annotation will be removed. Reanalyze to update findings.</p>
        <div className="modal-actions"><button disabled={busy} onClick={()=>setConfirmRemoval(false)}>Cancel</button><button disabled={busy||status.running} onClick={()=>act(removeDocumentation)}>Confirm removal</button></div>
      </>:<>
      <section className="effect-source-context" aria-label="Effect Source">
        <h4>Effect Source</h4>
        {documentationEditor.effect_source?<pre tabIndex={0}><RustPrototype text={documentationEditor.effect_source}/></pre>:<p>Effect source is unavailable. Reanalyze to refresh its location.</p>}
      </section>
      {documentationEditor.obligation_documentation&&<ObligationDocumentationPanel documentation={documentationEditor.obligation_documentation}/>}
      {!documentationEditor.obligation_documentation&&documentationEditor.effect_context&&<p className="effect-class-label" aria-label="Effect class">{effectContextLabel(documentationEditor.effect_context)}</p>}
      <PopupProducer key={documentationEditor.token} finding={selected?.id===documentationEditor.producerFinding?.id?documentationEditor.producerFinding:undefined} navigation={navigation}/>
      <textarea ref={placeCaretAtEnd} autoFocus disabled={busy} aria-label={documentationEditor.mode==='source'?'Source documentation':'Override documentation'} value={documentationEditor.document} onChange={e=>setDocumentationEditor({...documentationEditor,document:e.target.value})}/>
      {documentationEditor.mode==='override'&&<label className="override-destination">Override file{documentationEditor.destinations.length>1?<select aria-label="Override file" value={documentationEditor.destination} disabled={busy} onChange={e=>setDocumentationEditor({...documentationEditor,destination:e.target.value})}>{documentationEditor.destinations.map(d=><option key={d.path} value={d.path}>{displaySourcePath(d.path,root)}</option>)}</select>:<small>{displaySourcePath(documentationEditor.destination,root)}</small>}</label>}
      <div className="modal-actions">{documentationEditor.can_remove&&<button disabled={busy||status.running} onClick={()=>setConfirmRemoval(true)}>{documentationEditor.mode==='source'?(documentationEditor.action==='justification'?'Remove justification':'Remove obligation'):'Remove override'}</button>}<button disabled={busy} onClick={()=>setDocumentationEditor(undefined)}>Cancel</button><button className="primary" disabled={busy||status.running} onClick={()=>act(async()=>{if(documentationEditor.mode==='override'&&!documentationEditor.destinations.find(d=>d.path===documentationEditor.destination)?.exists){setCreateFile(true);return;}await commitDocumentation();})}>Save</button></div>
      </>}
      </>:<>
      {error&&<p role="alert">{error}</p>}
      <p>Choose a name for the override file. It will be saved beside the active configuration.</p>
      <label className="override-destination">Filename<input autoFocus aria-label="Override filename" value={overrideFilename} disabled={busy} onChange={e=>setOverrideFilename(e.target.value)}/></label>
      <div className="modal-actions"><button disabled={busy} onClick={()=>setCreateFile(false)}>Cancel</button><button className="primary" disabled={busy||status.running||!overrideFilename.trim()} onClick={()=>act(()=>commitDocumentation(overrideFilename))}>Create &amp; save</button></div>
      </>}
    </DocumentationPanel>}
  </div>;
}
createRoot(document.getElementById('root')!).render(<App/>);
