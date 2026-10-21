import React, {useEffect, useLayoutEffect, useRef, useState} from 'react';
import {createRoot} from 'react-dom/client';
import {EditorView, basicSetup} from 'codemirror';
import {EditorState, StateField, StateEffect} from '@codemirror/state';
import {Decoration, WidgetType} from '@codemirror/view';
import {rust} from '@codemirror/lang-rust';
import './style.css';

type Location = {path:string; start:number; end:number; available:boolean};
type Buffer = {path:string; content:string; original:string; revision:number; writable:boolean; conflict:boolean};
type Target = {action:string; location:Location};
type TemplateEdit = {path:string; revision:number; start:number; end:number; text:string; cursor:number};
type Finding = {id:string; crate_name:string; effect?:string;kind:string;class?:string;level:string;root?:string;trace_id?:string;reason:string;requirements:string[];missing_requirements:string[];display_trace:string[]; audit?:{obligation:string; justification:string; source?:Location; root?:Location; contract?:Location; targets:Target[]; trace:{caller:string; target?:string; kind:string; location?:Location}[]}};
type Summary = {id:string; crate_name:string; root:string; reason:string; level:string; effect:string; class:string; path?:string};
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
  constructor(readonly action:string, readonly run:()=>void) { super(); }
  toDOM() {
    const element=document.createElement('div');element.className='inline-prompt';
    const button=document.createElement('button');button.type='button';
    const justify=this.action==='justification';
    button.textContent=justify?'✓ Justify here':'↑ Propagate to callers';
    button.setAttribute('aria-label',justify?'Justify here':'Propagate to callers');
    button.addEventListener('click',this.run);
    const hint=document.createElement('span');
    hint.textContent=justify?"Explain why this is valid":"Document the caller's obligation";
    element.append(button,hint);return element;
  }
  ignoreEvent() { return true; }
}
function bytePosition(text:string, offset:number) { return new TextDecoder().decode(new TextEncoder().encode(text).slice(0,offset)).length; }
function Editor({buffer, location:target, onChange, finding, enabled, prepare, onError}:{buffer:Buffer; location?:Location; onChange:(text:string)=>void; finding?:Finding; enabled:boolean; prepare:(target:Target)=>Promise<TemplateEdit>; onError:(error:string)=>void}) {
  const holder = useRef<HTMLDivElement>(null), editorRef=useRef<EditorView | undefined>(undefined);
  const callback = useRef(onChange); callback.current = onChange;
  const prepareRef=useRef(prepare);prepareRef.current=prepare;
  const errorRef=useRef(onError);errorRef.current=onError;
  useEffect(()=>{
    if (!holder.current) return;
    let active=true;
    let view:EditorView;
    const widgets=(buffer.writable && !buffer.conflict && buffer.content===buffer.original ? finding?.audit?.targets || [] : []).filter(t=>t.location.path===buffer.path && t.location.available).flatMap(t=>{
      const position=bytePosition(buffer.content,t.location.start);
      const lineStart=buffer.content.lastIndexOf('\n',position-1)+1;
      if(buffer.content.slice(lineStart,position).trim())return [];
      const widget=new DocumentationPrompt(t.action,()=>{
        const snapshot=view.state.doc.toString();
        prepareRef.current(t).then(edit=>{
          if(!active)return;
          if(view.state.doc.toString()!==snapshot || edit.path!==buffer.path || edit.revision!==buffer.revision)throw Error('Source changed while preparing the template. Reanalyze before retrying.');
          const from=bytePosition(snapshot,edit.start),to=bytePosition(snapshot,edit.end);
          const updated=snapshot.slice(0,from)+edit.text+snapshot.slice(to);
          const cursor=bytePosition(updated,edit.cursor);
          view.dispatch({changes:edit.text?{from,to,insert:edit.text}:undefined,selection:{anchor:cursor},effects:EditorView.scrollIntoView(cursor,{y:'center'}),userEvent:'input'});
          view.focus();
        }).catch(e=>{if(active)errorRef.current(String(e));});
      });
      return [Decoration.widget({widget,block:true,side:-1}).range(lineStart)];
    });
    const originalPrompts=Decoration.set(widgets,true);
    const prompts=StateField.define({
      create:()=>({enabled,decorations:enabled?originalPrompts:Decoration.none}),
      update:(value,tr)=>{
        let allowed=value.enabled;
        for(const effect of tr.effects)if(effect.is(setPromptsEnabled))allowed=effect.value;
        if(!tr.docChanged && allowed===value.enabled)return value;
        return {enabled:allowed,decorations:allowed && tr.newDoc.toString()===buffer.original?originalPrompts:Decoration.none};
      },
      provide:field=>EditorView.decorations.from(field,value=>value.decorations),
    });
    view = new EditorView({parent:holder.current, state:EditorState.create({doc:buffer.content, extensions:[basicSetup,rust(),prompts, EditorView.lineWrapping, EditorState.readOnly.of(!buffer.writable), EditorView.updateListener.of(u=>{if(u.docChanged) callback.current(u.state.doc.toString());})]})});
    editorRef.current=view;
    if(target?.available && target.path === buffer.path && buffer.content === buffer.original) {
      const from = bytePosition(buffer.content,target.start),to=bytePosition(buffer.content,target.end);
      if (to <= view.state.doc.length) view.dispatch({selection:{anchor:from,head:to},effects:EditorView.scrollIntoView(from,{y:'center'})});
    }
    return ()=>{active=false;editorRef.current=undefined;view.destroy();};
  },[buffer.path,buffer.revision,target?.start,finding?.id]);
  useEffect(()=>{editorRef.current?.dispatch({effects:setPromptsEnabled.of(enabled)});},[enabled]);
  return <div className="editor" ref={holder} aria-label="Rust source editor"/>;
}
function App() {
  const [root,setRoot]=useState(''); const [status,setStatus]=useState<Status>({generation:0,running:false,stale:true,status:'connecting',count:0,log:''});
  const [items,setItems]=useState<Summary[]>([]),[total,setTotal]=useState(0),[effects,setEffects]=useState<string[]>([]);
  const [query,setQuery]=useState(''),[effect,setEffect]=useState(''),[level,setLevel]=useState(''),[kind,setKind]=useState(''),[page,setPage]=useState(0);
  const [selected,setSelected]=useState<Finding>(),[buffer,setBuffer]=useState<Buffer>(),[text,setText]=useState(''),[target,setTarget]=useState<Location>();
  const [drafts,setDrafts]=useState<Buffer[]>([]),[diff,setDiff]=useState(''),[view,setView]=useState<'source'|'changes'>('source');
  const [error,setError]=useState(''),[busy,setBusy]=useState(false),[logs,setLogs]=useState(false);
  const [nav,setNav]=useState<Location[]>([]);
  const detailsScroll = useRef<HTMLDivElement>(null);
  useLayoutEffect(()=>{detailsScroll.current?.scrollTo({top:0});},[selected?.id]);
  const unsaved = !!buffer && text !== buffer.content;
  async function act(work:()=>Promise<void>) {setBusy(true);setError('');try{await work();}catch(e){setError(String(e));}finally{setBusy(false);}}
  async function loadFindings(){const value=await api('findings?'+new URLSearchParams({q:query,effect,level,class:kind,offset:String(page*100)}));setItems(value.items);setTotal(value.total);setEffects(value.effects);}
  async function refreshDrafts(){setDrafts(await api('drafts'));}
  async function save(){if(!buffer)return; const updated=await api('buffer',{path:buffer.path,revision:buffer.revision,content:text});setBuffer(updated);await refreshDrafts();return updated as Buffer;}
  async function open(loc:Location, remember=true){
    if(unsaved)await save();
    if(remember && target) setNav(n=>[...n,target]);
    const next=await api('buffer?'+new URLSearchParams({path:loc.path}));setBuffer(next);setText(next.content);setTarget(loc);setView('source');setDiff('');
  }
  async function choose(item:Summary){const f:Finding=await api('finding?'+new URLSearchParams({id:item.id}));setSelected(f);const loc=f.audit?.source || f.audit?.root;if(loc)await open(loc);}
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
  useEffect(()=>{loadFindings().catch(e=>setError(String(e)));if(!status.running)refreshDrafts().catch(e=>setError(String(e)));},[query,effect,level,kind,page,status.generation,status.running]);
  useEffect(()=>{setPage(0)},[query,effect,level,kind]);
  useEffect(()=>{setSelected(undefined)},[status.generation]);
  useEffect(()=>{const warn=(e:BeforeUnloadEvent)=>{if(unsaved){e.preventDefault();}};window.addEventListener('beforeunload',warn);return()=>window.removeEventListener('beforeunload',warn)},[unsaved]);
  async function review(draft?:Buffer){if(unsaved&&draft&&draft.path!==buffer?.path)await save();let b=draft||buffer;if(!b)return;if(unsaved&&buffer?.path===b.path)b=await save()||b;setBuffer(b);setText(b.content);setDiff((await api('diff?'+new URLSearchParams({path:b.path}))).diff);setView('changes');}
  const groups = new Map<string,Summary[]>();for(const item of items){const key=item.path||item.root||item.crate_name;groups.set(key,[...(groups.get(key)||[]),item]);}
  return <div className="app">
    <header><div className="brand"><b>sniff-test</b><span> / audit</span></div><span className="workspace" title={root}>{root}</span><span className={'status '+status.status}>{status.status}{status.stale?' · stale':''}</span><button disabled={status.running||busy} onClick={()=>act(async()=>{await api('analysis',{});})}>↻ Reanalyze</button></header>
    {error&&<div className="error" role="alert">{error}<button onClick={()=>setError('')}>Dismiss</button></div>}
    <div className="layout"><aside className="findings"><div className="section-title">FINDINGS <span>{total}</span></div>
      <input aria-label="Search findings" placeholder="Search files, roots, crates…" value={query} onChange={e=>setQuery(e.target.value)}/>
      <div className="filters"><select aria-label="Effect" value={effect} onChange={e=>setEffect(e.target.value)}><option value="">All effects</option>{effects.map(e=><option key={e}>{e}</option>)}</select><select aria-label="Severity" value={level} onChange={e=>setLevel(e.target.value)}><option value="">All levels</option><option>warn</option><option>deny</option></select></div>
      <select aria-label="Finding class" value={kind} onChange={e=>setKind(e.target.value)}><option value="">All finding classes</option>{['concrete-operation','concrete-invocation','documented-obligation','undocumented-invocation','unresolved-call-target','analysis-incomplete','ambiguous-marker','ambiguous-requirement'].map(k=><option key={k}>{k}</option>)}</select>
      <div className="finding-list">{[...groups].map(([path,rows])=><section key={path}><div className="group" title={path}>{path.replace(root+'/','')} <span>{rows.length}</span></div>{rows.map(item=><button className={'finding '+(selected?.id===item.id?'selected':'')} key={item.id} onClick={()=>act(()=>choose(item))}><span className="badge">{item.effect||item.class}</span><strong>{item.root||item.crate_name}</strong><small>{item.reason}</small></button>)}</section>)}{!items.length&&<div className="empty">{status.running?'Analyzing the workspace…':status.status==='complete'?'No matching findings.':'No findings available. Check analysis output.'}</div>}</div>
      <div className="pagination"><button disabled={page===0} onClick={()=>setPage(p=>p-1)}>←</button><span>{page+1} / {Math.max(1,Math.ceil(total/100))}</span><button disabled={(page+1)*100>=total} onClick={()=>setPage(p=>p+1)}>→</button></div>
      <div className="section-title">SAVED DRAFTS <span>{drafts.length}</span></div>{drafts.map(d=><button className="draft" key={d.path} onClick={()=>act(()=>review(d))}>{d.path.replace(root+'/','')}{d.conflict?' · conflict':' · modified'}</button>)}
    </aside>
    <main><div className="toolbar"><button disabled={!nav.length||busy} onClick={()=>act(async()=>{const previous=nav[nav.length-1];setNav(n=>n.slice(0,-1));await open(previous,false);})}>← Back</button><span className="filename">{buffer?.path.replace(root+'/','')||'Source workspace'}</span>{buffer&&<><button onClick={()=>setView('source')}>Source</button><button onClick={()=>act(()=>review())}>Review diff</button></>}</div>
      {buffer?<><div className="buffer-state">{buffer.writable?'Workspace source':'Read-only dependency'}{unsaved?' · unsaved editor changes':buffer.content!==buffer.original?' · draft saved':''}{buffer.conflict&&<strong> · External file changed. Copy your draft, discard it, then reapply your changes to the current source.</strong>}</div>
      {view==='source'?<Editor buffer={buffer} location={target} onChange={setText} finding={selected} enabled={!status.running&&!status.stale&&!unsaved} onError={setError} prepare={async t=>{
        if(!selected||!buffer||unsaved)throw Error('Save or discard editor changes before inserting a template.');
        return api('template',{id:selected.id,action:t.action,revision:buffer.revision});
      }}/>:<pre className="diff">{diff||'No changes to review.'}</pre>}
      <footer>{view==='source'?<button className="primary" disabled={!buffer.writable||!unsaved||busy||status.running} onClick={()=>act(async()=>{await save();})}>Save draft</button>:<button className="primary" disabled={buffer.conflict||!diff||busy||status.running} onClick={()=>act(async()=>{await api('apply',{path:buffer.path,revision:buffer.revision});await open({path:buffer.path,start:0,end:0,available:true});await refreshDrafts();})}>Apply file & reanalyze</button>}<button disabled={busy||status.running||buffer.content===buffer.original} onClick={()=>act(async()=>{await api('discard',{path:buffer.path,revision:buffer.revision});await open({path:buffer.path,start:0,end:0,available:true});await refreshDrafts();})}>Discard draft</button><small>Drafts stay separate from source until applied.</small></footer></>:<div className="welcome"><span className="eyebrow">WORKSPACE AUDIT</span><h1>Follow the effect.<br/>Document the reasoning.</h1><p>Select a finding to explore its source, trace the calls, and draft a justification or obligation.</p><div className="steps">01 Inspect &nbsp; → &nbsp; 02 Draft &nbsp; → &nbsp; 03 Review</div></div>}
    </main>
    <aside className="details" aria-label="Effect details">{selected?<><section className="effect-summary" aria-label="Selected effect"><div className="section-title">FINDING DETAILS</div><p>{selected.reason}</p><small>{selected.crate_name} · trace {selected.trace_id||'unavailable'}</small></section>
      <div className="details-scroll" ref={detailsScroll} tabIndex={0} aria-label="Navigation and call trace"><h3>Navigate</h3>{[['Report root',selected.audit?.root],['Effect source',selected.audit?.source],['Contract',selected.audit?.contract]].map(([label,l])=><button className="link" key={label as string} disabled={!l} onClick={()=>act(()=>open(l as Location))}>{label as string}{!(l as Location)?.available?' · unavailable':''}</button>)}
      {selected.audit?.targets.map(t=><button className="link" key={t.action} onClick={()=>act(()=>open(t.location))}>{t.action==='justification'?'Justification location':'Obligation location'}</button>)}
      {buffer&&!buffer.writable&&<p className="hint">Dependency source is read-only. Contract documentation can be supplied through an override file.</p>}
      {selected.audit&&!selected.audit.targets.length&&<p className="hint">No verified documentation attachment location is available. Inspect the source and edit manually where appropriate.</p>}
      {unsaved||buffer?.content!==buffer?.original?<p className="hint">Revert to the original source to restore inline prompts, or apply edits and reanalyze.</p>:null}
      <h3>Call trace</h3><ol className="trace">{selected.audit?.trace.map((step,i)=><li key={i}><button disabled={!step.location} onClick={()=>act(()=>open(step.location!))}>{step.caller}<span>{step.kind} → {step.target||'effect operation'}</span></button></li>)}</ol></div>
    </>:<div className="empty">Select a finding to inspect its contract and call trace.</div>}</aside></div>
    <div className="analysis-log"><button onClick={()=>setLogs(!logs)}>{logs?'▾':'▸'} Analysis output</button><span>{status.count} findings · {drafts.length} saved drafts</span>{logs&&<pre>{status.log||'Waiting for analysis output…'}</pre>}</div>
  </div>;
}
createRoot(document.getElementById('root')!).render(<App/>);
