import {rustLanguage} from '@codemirror/lang-rust';
import type {SyntaxNode} from '@lezer/common';
import type {Hover} from 'vscode-languageserver-protocol';

export type ProducerKind='Option'|'Result';
export type ProducerDocumentation={markdown:string;prototype?:string};
export type ProducerSource={path:string;start:number;end:number;available:boolean;hash?:string;approximate?:boolean};

export function unwrapKind(functions:(string|undefined)[]):ProducerKind|undefined {
  for(let name of functions){
    if(!name)continue;
    // Report paths may include generic arguments on the standard enum.
    while(/<[^<>]*>/.test(name))name=name.replace(/<[^<>]*>/g,'');
    name=name.replace(/::(?=::)/g,'');
    if(name==='core::option::Option::unwrap')return 'Option';
    if(name==='core::result::Result::unwrap')return 'Result';
  }
}

/** Positions are UTF-16 offsets in the normalized document sent to the LSP. */
export function producerPosition(source:string,start:number,end:number):number|undefined {
  const tree=rustLanguage.parser.parse(source),calls:SyntaxNode[]=[];
  tree.iterate({enter(node){
    if(node.name!=='CallExpression')return;
    const field=node.node.firstChild,args=node.node.lastChild;
    if(field?.name==='FieldExpression' && field.lastChild?.name==='FieldIdentifier'
      && source.slice(field.lastChild.from,field.lastChild.to)==='unwrap'
      && args?.name==='ArgList' && /^\(\s*\)$/.test(source.slice(args.from,args.to)))calls.push(node.node);
  }});
  const enclosing=calls.filter(node=>node.from<=start&&node.to>=end).sort((a,b)=>(a.to-a.from)-(b.to-b.from));
  const contained=calls.filter(node=>node.from>=start&&node.to<=end);
  const call=enclosing[0] || (contained.length===1?contained[0]:undefined);
  let receiver=call?.firstChild?.firstChild;
  while(receiver?.name==='ParenthesizedExpression')receiver=receiver.getChild('CallExpression') || receiver.getChild('ParenthesizedExpression') || undefined;
  if(receiver?.name!=='CallExpression')return;
  let callee=receiver.firstChild;
  if(callee?.name==='GenericFunction')callee=callee.firstChild;
  if(callee?.name==='FieldExpression' || callee?.name==='ScopedIdentifier')callee=callee.lastChild;
  if(callee && /^(Identifier|FieldIdentifier)$/.test(callee.name))return callee.from;
}

export function producerDocumentation(hover:Hover|null):ProducerDocumentation|undefined {
  if(!hover)return;
  const contents=hover.contents;
  const marked=(value:string|{language:string;value:string})=>typeof value==='string'?value:'```'+value.language+'\n'+value.value+'\n```';
  const markdown=Array.isArray(contents)?contents.map(marked).join('\n\n')
    :typeof contents==='string'?contents:'kind' in contents?contents.value:marked(contents);
  if(!markdown.trim())return;
  // rust-analyzer places namespace/impl blocks and the declaration before a
  // horizontal rule. Search only that header so examples remain documentation.
  const divider=/^\s*---+\s*$/m.exec(markdown);
  const header=markdown.slice(0,divider?.index ?? markdown.length);
  const blocks=[...header.matchAll(/^(`{3,}|~{3,})(?:rust|rs)?\s*\n([\s\S]*?)^\1\s*$/gm)];
  const declaration=blocks.find(block=>/\bfn\s+(?:r#)?[\p{L}_]/u.test(block[2])
    && header.slice(0,block.index).replace(/^(`{3,}|~{3,})(?:rust|rs)?\s*\n[\s\S]*?^\1\s*$/gm,'').trim()==='');
  if(declaration){
    const prototype=declaration[2].trim();
    const after=divider?markdown.slice(divider.index+divider[0].length):markdown.slice(declaration.index!+declaration[0].length);
    return {markdown:after.trim(),prototype};
  }
  // A signature-only plaintext hover is also useful when Markdown is unavailable.
  if(!markdown.includes('\n') && /\bfn\s+[\p{L}_]/u.test(markdown))return {markdown:'',prototype:markdown.trim()};
  return {markdown};
}

export function sourcePosition(source:string,offset:number):number {
  return new TextDecoder('utf-8',{ignoreBOM:true}).decode(new TextEncoder().encode(source).slice(0,offset)).replace(/\r\n/g,'\n').length;
}
