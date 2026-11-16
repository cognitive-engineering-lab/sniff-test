import type {Nodes, Root} from 'mdast';

function headingText(node:Nodes):string {
  if('value' in node)return node.value;
  if('children' in node)return node.children.map(headingText).join('');
  return '';
}

/** Prefer failure documentation while retaining Markdown link definitions. */
export function producerErrorSections({fallbackTitle}:{fallbackTitle?:string}={}) {
  return (tree:Root)=>{
    const selected:Root['children']=[];
    let depth:number|undefined,found=false;
    for(const node of tree.children){
      if(node.type==='heading'){
        if(depth!==undefined&&node.depth<=depth)depth=undefined;
        if(/^errors?$/i.test(headingText(node).trim())){
          found=true;
          depth??=node.depth;
        }
      }
      if(depth!==undefined||node.type==='definition')selected.push(node);
    }
    if(found)tree.children=selected;
    else if(fallbackTitle)tree.children.unshift({
      type:'heading',depth:1,children:[{type:'text',value:fallbackTitle}],
      data:{hProperties:{className:['producer-title']}},
    });
  };
}
