import {syntaxTree} from '@codemirror/language';
import {ChangeSet, Text, StateEffect, StateField} from '@codemirror/state';
import {EditorView, keymap, Decoration, ViewPlugin, ViewUpdate} from '@codemirror/view';
import type {Location, LocationLink, DefinitionParams} from 'vscode-languageserver-protocol';
import {LSPClient, LSPPlugin, Workspace, WorkspaceFile} from '@codemirror/lsp-client';

export function fileUri(path:string) { return 'file://'+path.split('/').map(encodeURIComponent).join('/'); }
export function filePath(uri:string) {
  const url=new URL(uri);
  if(url.protocol!=='file:' || (url.hostname && url.hostname!=='localhost'))throw Error('Definition is not a local file.');
  return decodeURIComponent(url.pathname);
}
type OpenFile = WorkspaceFile & {view:EditorView|null; pending?:Text};
// Retain documents after leaving their editor so rust-analyzer can keep its
// workspace synchronized with saved files and the active editor.
class AuditWorkspace extends Workspace {
  files:OpenFile[]=[];
  constructor(client:LSPClient, readonly display:(uri:string)=>Promise<EditorView|null>, readonly changed:()=>void){super(client);}
  displayFile(uri:string){return this.display(uri);}
  syncFiles(){
    const updates=[];
    for(const file of this.files){
      const plugin=file.view && LSPPlugin.get(file.view);
      const doc=file.view?.state.doc || file.pending || file.doc;
      if(!doc.eq(file.doc)){
        const changes=plugin?.unsyncedChanges || ChangeSet.of({from:0,to:file.doc.length,insert:doc},file.doc.length);
        updates.push({file,prevDoc:file.doc,changes});file.doc=doc;file.version++;
      }
      plugin?.clear();file.pending=undefined;
    }
    if(updates.length)this.changed();
    return updates;
  }
  setDocument(path:string,content:string){
    const uri=fileUri(path),existing=this.getFile(uri) as OpenFile|null;
    if(existing){if(!existing.view)existing.pending=Text.of(content.replace(/\r\n/g,'\n').split('\n'));return;}
    const file:OpenFile={uri,languageId:'rust',version:0,doc:Text.of(content.replace(/\r\n/g,'\n').split('\n')),view:null,getView(){return this.view;}};
    this.files.push(file);this.client.didOpen(file);
  }
  openFile(uri:string,languageId:string,view:EditorView){
    let file=this.getFile(uri) as OpenFile|null;
    if(file){
      // Reloading a file from disk may replace its whole contents.
      if(!file.doc.eq(view.state.doc)){this.changed();this.client.didClose(uri);file.doc=view.state.doc;file.version++;this.client.didOpen(file);}
      file.view=view;file.pending=undefined;
    }else{
      file={uri,languageId,version:0,doc:view.state.doc,view,getView(){return this.view;}};
      this.files.push(file);this.client.didOpen(file);
    }
  }
  closeFile(uri:string,view:EditorView){this.client.sync();const file=this.getFile(uri) as OpenFile|null;if(file?.view===view)file.view=null;}
}

type Definition = {uri:string; range:Location['range']};
type Identifier = {from:number; to:number};
const setDefinitionHover=StateEffect.define<Identifier|null>();
const definitionHover=StateField.define({
  create:()=>Decoration.none,
  update(value,transaction){
    if(transaction.docChanged)value=Decoration.none;
    for(const effect of transaction.effects)if(effect.is(setDefinitionHover)){
      value=effect.value?Decoration.set([Decoration.mark({class:'cm-definition-link'}).range(effect.value.from,effect.value.to)]):Decoration.none;
    }
    return value;
  },
  provide:field=>EditorView.decorations.from(field),
});
function identifierAt(view:EditorView,position:number):Identifier|null {
  for(const side of [1,-1] as const){
    const node=syntaxTree(view.state).resolveInner(position,side);
    if(/^(Identifier|FieldIdentifier|TypeIdentifier|ScopeIdentifier|BoundIdentifier)$/.test(node.name)){
      // The Rust grammar can split Unicode identifiers into adjacent nodes.
      const word=view.state.wordAt(position);
      return {from:Math.min(node.from,word?.from ?? node.from),to:Math.max(node.to,word?.to ?? node.to)};
    }
  }
  return null;
}

class DefinitionHover {
  private pointer?:{x:number;y:number};
  private modifier=false;
  private timer?:ReturnType<typeof setTimeout>;
  private generation=0;
  private candidate?:Identifier;
  private destroyed=false;
  constructor(readonly view:EditorView,readonly navigation:Navigation){
    window.addEventListener('keydown',this.key);
    window.addEventListener('keyup',this.key);
    window.addEventListener('blur',this.blur);
    view.scrollDOM.addEventListener('scroll',this.scroll);
    navigation.onDisconnect.add(this.leave);
    navigation.onInvalidate.add(this.invalidate);
  }
  private clear(){
    clearTimeout(this.timer);this.generation++;this.candidate=undefined;
    if(this.view.state.field(definitionHover).size)this.view.dispatch({effects:setDefinitionHover.of(null)});
  }
  private invalidate=()=>{this.clear();this.refresh();};
  private scroll=()=>{
    // A scroll event can arrive after mousemove when a trace opens. Keep the
    // physical pointer and resolve it again against the settled viewport.
    queueMicrotask(()=>{if(!this.destroyed)this.invalidate();});
  };
  private key=(event:KeyboardEvent)=>{
    const modifier=event.metaKey || event.ctrlKey;
    if(modifier===this.modifier)return;
    this.modifier=modifier;this.refresh();
  };
  private blur=()=>{this.modifier=false;this.leave();};
  leave=()=>{this.pointer=undefined;this.clear();};
  move(event:MouseEvent){
    this.pointer={x:event.clientX,y:event.clientY};this.modifier=event.metaKey || event.ctrlKey;this.refresh();
  }
  private refresh(){
    const position=this.pointer && this.view.posAtCoords(this.pointer);
    const candidate=position==null?null:identifierAt(this.view,position);
    const start=candidate && this.view.coordsAtPos(candidate.from),end=candidate && this.view.coordsAtPos(candidate.to);
    // posAtCoords rounds to text positions: don't turn adjacent whitespace into a link.
    if(!this.modifier || !this.navigation.client.connected || !candidate || !start || !end || !this.pointer || this.pointer.x<start.left || this.pointer.x>end.left || this.pointer.y<start.top || this.pointer.y>start.bottom){this.clear();return;}
    if(this.candidate?.from===candidate.from && this.candidate.to===candidate.to)return;
    this.clear();this.candidate=candidate;
    const generation=this.generation,doc=this.view.state.doc;
    this.timer=setTimeout(()=>{
      this.navigation.lookupDefinition(this.view,candidate.from).then(result=>{
        if(result && generation===this.generation && this.modifier && this.view.state.doc===doc && this.navigation.client.connected){
          this.view.dispatch({effects:setDefinitionHover.of(candidate)});
        }
        if(!result && generation===this.generation)this.candidate=undefined;
      }).catch(()=>{if(generation===this.generation)this.candidate=undefined;}); // Retry on the next gesture, not a polling loop.
    },100);
  }
  update(update:ViewUpdate){
    if(update.docChanged || update.viewportChanged){
      // The StateField clears on edits; avoid dispatching during a view update.
      clearTimeout(this.timer);this.generation++;this.candidate=undefined;
      if(update.docChanged)this.pointer=undefined;
      else this.scroll();
    }
  }
  destroy(){
    this.destroyed=true;
    clearTimeout(this.timer);this.generation++;
    window.removeEventListener('keydown',this.key);window.removeEventListener('keyup',this.key);window.removeEventListener('blur',this.blur);
    this.view.scrollDOM.removeEventListener('scroll',this.scroll);this.navigation.onDisconnect.delete(this.leave);this.navigation.onInvalidate.delete(this.invalidate);
  }
}

export class Navigation {
  readonly client:LSPClient;
  readonly onDisconnect=new Set<()=>void>();
  readonly onInvalidate=new Set<()=>void>();
  private revision=0;
  private quiescent?:boolean;
  invalidate(){
    this.revision++;this.definitions=new WeakMap();
    // Synchronization can happen during a CodeMirror update.
    queueMicrotask(()=>{if(!this.stopped)for(const refresh of this.onInvalidate)refresh();});
  }
  private definitions=new WeakMap<EditorView,{doc:Text;from:number;to:number;result:Promise<Definition|null>}>();
  private controller=new AbortController();
  private listeners=new Set<(message:string)=>void>();
  private queue=Promise.resolve();
  private id=crypto.randomUUID();
  private stopped=false;
  constructor(readonly token:string,root:string,display:(uri:string)=>Promise<EditorView|null>,readonly status:(text:string)=>void,readonly remember:(view:EditorView)=>void){
    this.client=new LSPClient({rootUri:fileUri(root),timeout:30000,initializationOptions:{checkOnSave:false,check:{enable:false}},workspace:client=>new AuditWorkspace(client,display,()=>this.invalidate()),
      extensions:[{clientCapabilities:{experimental:{serverStatusNotification:true}}}],
      notificationHandlers:{'experimental/serverStatus':(_client,value)=>{
        if(this.quiescent!==value.quiescent){this.quiescent=value.quiescent;this.invalidate();}
        if(!this.stopped)this.status(value.quiescent?'Rust navigation ready · ⌘/Ctrl-click or F12':'Indexing Rust workspace…');
        if(value.health!=='ok' && value.message && !this.stopped)this.status('Rust navigation: '+value.message);
        return true;
      }},
    });
  }
  async start(){
    try{
      this.status('Starting Rust navigation…');
      const response=await fetch('/api/v1/lsp/events?id='+this.id,{headers:{'x-audit-token':this.token},signal:this.controller.signal});
      if(!response.ok)throw Error(await response.text());
      this.client.connect({send:message=>{
        this.queue=this.queue.then(async()=>{
          const result=await fetch('/api/v1/lsp/messages?id='+this.id,{method:'POST',headers:{'x-audit-token':this.token,'Content-Type':'application/json'},body:message,signal:this.controller.signal});
          if(!result.ok)throw Error(await result.text());
        }).catch(error=>this.fail(error));
      },subscribe:listener=>{this.listeners.add(listener);},unsubscribe:listener=>{this.listeners.delete(listener);}});
      this.client.initializing.then(()=>{if(!this.stopped)this.status('Indexing Rust workspace…');}).catch(error=>this.fail(error));
      const reader=response.body!.getReader(),decoder=new TextDecoder();let pending='';
      while(true){
        const {value,done}=await reader.read();if(done)throw Error('rust-analyzer disconnected');
        pending+=decoder.decode(value,{stream:true});let split;
        while((split=pending.indexOf('\n\n'))>=0){
          const event=pending.slice(0,split);pending=pending.slice(split+2);
          const data=event.split('\n').filter(line=>line.startsWith('data:')).map(line=>line.slice(5).trimStart()).join('\n');
          if(event.includes('event: failure'))throw Error(data);
          if(data)for(const listener of this.listeners)listener(data);
        }
      }
    }catch(error){this.fail(error);}
  }
  private fail(error:unknown){if(!this.stopped){this.status('Rust navigation unavailable: '+String(error));this.stop();}}
  stop(){this.revision++;for(const clear of this.onDisconnect)clear();this.definitions=new WeakMap();this.stopped=true;this.controller.abort();this.client.disconnect();}
  document(path:string,content:string){(this.client.workspace as AuditWorkspace).setDocument(path,content);this.client.sync();}
  lookupDefinition(view:EditorView,position:number):Promise<Definition|null>{
    const plugin=LSPPlugin.get(view);
    if(!plugin || !this.client.connected)return Promise.resolve(null);
    this.client.sync();
    const revision=this.revision;
    const token=identifierAt(view,position) || {from:position,to:position};
    const cached=this.definitions.get(view);
    if(cached?.doc===view.state.doc && cached.from===token.from && cached.to===token.to)return cached.result;
    const result=this.client.request<DefinitionParams,Location|Location[]|LocationLink[]|null>('textDocument/definition',{
      textDocument:{uri:plugin.uri},position:plugin.toPosition(position),
    }).then(response=>{
      if(revision!==this.revision)return null;
      const location=Array.isArray(response)?response[0]:response;
      if(!location)return null;
      const uri='targetUri' in location?location.targetUri:location.uri;
      filePath(uri); // Only destinations supported by the editor qualify as links.
      return {uri,range:'targetUri' in location?location.targetSelectionRange:location.range};
    });
    const entry={doc:view.state.doc,...token,result};this.definitions.set(view,entry);
    const evict=()=>{if(this.definitions.get(view)===entry)this.definitions.delete(view);};
    void result.then(value=>{if(!value)evict();},evict);
    return result;
  }
  private definition(view:EditorView){
    const plugin=LSPPlugin.get(view);
    if(!plugin || !this.client.connected)return false;
    this.client.sync();
    const doc=view.state.doc,selection=view.state.selection,revision=this.revision;
    this.client.withMapping(mapping=>this.lookupDefinition(view,selection.main.head).then(async result=>{
      // A response for an editor the user has left or changed must not redirect them.
      if(revision!==this.revision || this.client.workspace.getFile(plugin.uri)?.getView()!==view || !view.state.doc.eq(doc) || !view.state.selection.eq(selection))return;
      if(!result){this.status('No definition found at this position.');return;}
      const {uri,range}=result;
      this.remember(view);
      const target=uri===plugin.uri?view:await this.client.workspace.displayFile(uri);
      if(!target)return;
      const position=mapping.getMapping(uri)?mapping.mapPosition(uri,range.start):plugin.fromPosition(range.start,target.state.doc);
      target.dispatch({selection:{anchor:position},effects:EditorView.scrollIntoView(position,{y:'center'}),userEvent:'select.definition'});
      target.focus();
    })).catch(error=>{if(this.client.workspace.getFile(plugin.uri)?.getView()===view)plugin.reportError('Find definition failed',error);});
    return true;
  }
  extension(path:string){
    const hover=ViewPlugin.define(view=>new DefinitionHover(view,this),{eventHandlers:{mousemove(event){this.move(event);},mouseleave(){this.leave();},focusout(){this.leave();}}});
    return [definitionHover,hover,EditorView.updateListener.of(update=>{if(update.docChanged)this.invalidate();}),this.client.plugin(fileUri(path),'rust'),keymap.of([{key:'F12',run:view=>this.definition(view),preventDefault:true}]),EditorView.domEventHandlers({mousedown:(event,view)=>{
    if(event.button!==0 || !(event.metaKey || event.ctrlKey))return false;
    const position=view.posAtCoords({x:event.clientX,y:event.clientY});if(position===null)return false;
    view.dispatch({selection:{anchor:position}});this.definition(view);return true;
  }})];}
}
