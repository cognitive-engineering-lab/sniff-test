import React, {useLayoutEffect, useMemo, useRef} from 'react';
import {rustLanguage} from '@codemirror/lang-rust';
import {defaultHighlightStyle} from '@codemirror/language';
import {highlightTree} from '@lezer/highlight';
import {StyleModule} from 'style-mod';

export function RustPrototype({text}:{text:string}) {
  const code=useRef<HTMLElement>(null);
  const highlighted=useMemo(()=>{
    try {
      const pieces:React.ReactNode[]=[];
      let end=0;
      highlightTree(rustLanguage.parser.parse(text),defaultHighlightStyle,(from,to,classes)=>{
        if(from>end)pieces.push(text.slice(end,from));
        pieces.push(<span key={from} className={classes}>{text.slice(from,to)}</span>);
        end=to;
      });
      if(end<text.length)pieces.push(text.slice(end));
      return pieces;
    } catch {
      return text;
    }
  },[text]);
  useLayoutEffect(()=>{
    if(code.current&&defaultHighlightStyle.module) {
      StyleModule.mount(code.current.ownerDocument,defaultHighlightStyle.module);
    }
  },[]);
  return <code ref={code}>{highlighted}</code>;
}
