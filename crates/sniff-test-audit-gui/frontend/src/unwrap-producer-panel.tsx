import React, {useEffect, useState} from 'react';
import Markdown from 'react-markdown';
import {documentationComponents} from './obligation-documentation';
import {RustPrototype} from './rust-prototype';
import {producerErrorSections} from './producer-error-sections';
import type {Navigation} from './navigation';
import {producerDocumentation, producerPosition, sourcePosition, type ProducerDocumentation, type ProducerKind, type ProducerSource} from './unwrap-producer';

export function UnwrapProducerPanel({kind,source,navigation,readSource}:{kind:ProducerKind;source:ProducerSource;navigation?:Navigation;readSource:(path:string)=>Promise<{content:string;hash:string}>}) {
  const [context,setContext]=useState<ProducerDocumentation>();
  const [loading,setLoading]=useState(false);
  useEffect(()=>{
    let disposed=false,sequence=0;
    async function load(){
      const request=++sequence;
      setContext(undefined);setLoading(false);
      if(!navigation || !source.available || source.approximate || !source.hash)return;
      try {
        const buffer=await readSource(source.path);
        if(disposed || request!==sequence || buffer.hash!==source.hash)return;
        const content=buffer.content.replace(/\r\n/g,'\n');
        const position=producerPosition(content,sourcePosition(buffer.content,source.start),sourcePosition(buffer.content,source.end));
        if(position===undefined)return;
        setLoading(true);
        const hover=await navigation.hover(source.path,content,position);
        if(!disposed && request===sequence)setContext(producerDocumentation(hover));
      } catch { /* Optional context must never prevent documentation editing. */ }
      finally {if(!disposed && request===sequence)setLoading(false);}
    }
    const clear=()=>{sequence++;setContext(undefined);setLoading(false);};
    // Retry once the workspace settles, and discard context after edits.
    const invalidate=()=>{void load();};
    navigation?.onInvalidate.add(invalidate);navigation?.onDisconnect.add(clear);
    void load();
    return()=>{disposed=true;sequence++;navigation?.onInvalidate.delete(invalidate);navigation?.onDisconnect.delete(clear);};
  },[kind,source.path,source.start,source.end,source.hash,source.available,source.approximate,navigation,readSource]);
  if(!context&&!loading)return null;
  const title=kind+' Producer';
  return <section className="obligation-context producer-context" aria-label={title}>
    <div className="obligation-markdown" role="region" aria-label="Producer documentation" tabIndex={0}>
      {loading?<p role="status">Loading producer documentation…</p>:context?.markdown
        ?<Markdown components={documentationComponents} remarkPlugins={[[producerErrorSections,{fallbackTitle:title}]]} skipHtml>{context.markdown}</Markdown>
        :<p>No producer documentation available.</p>}
    </div>
    {context?.prototype&&<pre className="obligation-prototype" aria-label="Producer prototype" tabIndex={0}><RustPrototype text={context.prototype}/></pre>}
  </section>;
}
