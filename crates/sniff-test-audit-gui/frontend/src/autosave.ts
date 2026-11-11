export type Snapshot = {path:string; content:string; revision:number; writable:boolean};
export type SaveState = {status:'saved'|'pending'|'saving'|'failed'; error?:string};

/** One open document, with ordered writes and a trailing idle timer. */
export class Autosave<T extends Snapshot> {
  snapshot?:T;
  text='';
  private timer?:ReturnType<typeof setTimeout>;
  private flight?:Promise<void>;
  private failure?:string;
  private due=0;
  private disposed=false;
  constructor(private write:(snapshot:T,text:string)=>Promise<T>, private acknowledged:(snapshot:T)=>void, private changedState:(state:SaveState)=>void, private delay=1000) {}
  get pending(){return !!this.flight || !!this.snapshot && this.text!==this.snapshot.content;}
  load(snapshot:T,discard=false){
    if(this.flight)throw Error('Wait for the current save before reloading.');
    if(this.pending&&!discard)throw Error('Save the current edits before switching files.');
    this.clear();this.snapshot=snapshot;this.text=snapshot.content;this.failure=undefined;this.emit();
  }
  change(text:string){if(!this.snapshot?.writable)return;this.text=text;this.due=performance.now()+this.delay;this.clear();this.emit();this.schedule();}
  async flush(){
    this.clear();
    if(this.failure)throw Error(this.failure);
    while(this.pending){
      if(this.flight)await this.flight;
      else await this.send();
      this.clear();
    }
  }
  async retry(){this.failure=undefined;await this.flush();this.emit();}
  dispose(){this.disposed=true;this.clear();}
  private clear(){if(this.timer!==undefined)clearTimeout(this.timer);this.timer=undefined;}
  private emit(){if(!this.disposed)this.changedState({status:this.failure?'failed':this.flight?'saving':this.pending?'pending':'saved',error:this.failure});}
  private schedule(){
    if(this.disposed || this.failure || this.flight || !this.pending)return;
    this.clear();this.timer=setTimeout(()=>{this.timer=undefined;void this.send().catch(()=>{});},Math.max(0,this.due-performance.now()));
  }
  private send():Promise<void>{
    const snapshot=this.snapshot;
    if(!snapshot || !snapshot.writable || this.text===snapshot.content)return Promise.resolve();
    const text=this.text;
    this.flight=Promise.resolve().then(()=>this.write(snapshot,text)).then(next=>{
      this.snapshot=next;
      if(!this.disposed)this.acknowledged(next);
    }).catch(error=>{this.failure=String(error);throw error;}).finally(()=>{
      this.flight=undefined;this.emit();this.schedule();
    });
    this.emit();return this.flight;
  }
}
