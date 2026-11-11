import {rustLanguage} from '@codemirror/lang-rust';
import {ChangeSet, EditorSelection, EditorState, Prec, StateEffect, StateField, Text} from '@codemirror/state';
import {keymap} from '@codemirror/view';

/** Always continue real Rust line comments, including prefix-only lines. */
export const continueRustComments=Prec.highest(keymap.of([{key:'Enter',run:view=>{
  if(view.state.readOnly)return false;
  const source=view.state.doc.toString(),syntax=rustLanguage.parser.parse(source);
  const edits=view.state.selection.ranges.map(range=>{
    const line=view.state.doc.lineAt(range.from);
    const match=/^(\s*)(\/\/\/|\/\/!|\/\/)(?!\/)/.exec(line.text);
    if(!match || range.to>line.to || range.from<line.from+match[0].length)return undefined;
    const start=line.from+match[1].length,node=syntax.resolveInner(start,1);
    if(node.name!=='LineComment'||node.from!==start)return undefined;
    return {from:range.from,to:range.to,insert:Text.of(['',match[1]+match[2]+' '])};
  });
  if(edits.some(edit=>!edit))return false;
  let index=0;
  const changes=view.state.changeByRange(()=>{
    const edit=edits[index++]!;
    return {changes:edit,range:EditorSelection.cursor(edit.from+edit.insert.length)};
  });
  view.dispatch({...changes,scrollIntoView:true,userEvent:'input'});
  return true;
}}]));

type Candidate={position:number;action:string;external:boolean};
type Documentation={justification:string;obligation:string};
export const configureCommentEditing=StateEffect.define<{scope:string;candidates:Candidate[];documentation?:Documentation}>();
type EditingRegion={from:number;to:number};

function mergeRegions(regions:EditingRegion[]){
  const merged:EditingRegion[]=[];
  for(const region of regions.sort((a,b)=>a.from-b.from)){
    const last=merged.at(-1);
    if(last&&region.from<=last.to)last.to=Math.max(last.to,region.to);
    else merged.push({...region});
  }
  return merged;
}
/** Lives outside prompt reconfiguration so save acknowledgments cannot reset an edit. */
export const commentEditing=StateField.define({
  create:()=>({scope:'',candidates:[] as Candidate[],documentation:undefined as Documentation|undefined,regions:[] as EditingRegion[]}),
  update:(previous,tr)=>{
    if(!tr.docChanged&&!tr.selection&&!tr.effects.some(effect=>effect.is(configureCommentEditing)))return previous;
    let value={...previous,candidates:previous.candidates.map(c=>({...c,position:tr.changes.mapPos(c.position,1)})),
      regions:previous.regions.map(r=>({from:tr.changes.mapPos(r.from,-1),to:tr.changes.mapPos(r.to,1)}))};
    for(const effect of tr.effects)if(effect.is(configureCommentEditing)){
      value={...effect.value,documentation:effect.value.documentation,regions:value.scope===effect.value.scope?value.regions:[]};
    }
    const source=tr.state.doc.toString();
    const local=(r:EditingRegion)=>r.from<r.to && tr.state.selection.ranges.some(s=>s.from<r.to&&s.to>=r.from);
    // Keep partial comments editable, but whitespace alone means all documentation is gone.
    const syntax=rustLanguage.parser.parse(source);
    const clean=(r:EditingRegion)=>{
      let at=r.from,hasComment=false;
      while(at<r.to){
        if(/\s/.test(source[at])){at++;continue;}
        const node=syntax.resolveInner(at,1);
        if(node.name!=='LineComment'||node.from!==at)return false;
        hasComment=true;
        at=node.to;
      }
      return hasComment;
    };
    value.regions=value.regions.filter(r=>local(r)&&clean(r));
    for(const attachment of sourcePromptAttachments(source,value.candidates,value.documentation,syntax)){
      if(!attachment.attached || attachment.commentStart===undefined)continue;
      const region={from:attachment.commentStart,to:attachment.lineStart};
      if(local(region)&&!value.regions.some(r=>r.from===region.from&&r.to===region.to))value.regions.push(region);
    }
    return value;
  },
  provide:field=>EditorState.transactionFilter.of(tr=>{
    if(tr.startState.readOnly || !tr.docChanged || !(tr.isUserEvent('delete')||tr.isUserEvent('input')))return tr;
    const emptied=tr.startState.field(field).regions.flatMap(region=>{
      let deleted=false;
      tr.changes.iterChangedRanges((from,to)=>{if(from<to&&from<region.to&&to>region.from)deleted=true;});
      if(!deleted)return [];
      const from=tr.changes.mapPos(region.from,-1),to=tr.changes.mapPos(region.to,1);
      // Only remove complete lines inside the old region, never neighboring layout or code.
      if(from>=to || tr.newDoc.lineAt(from).from!==from || tr.newDoc.lineAt(to).from!==to || tr.newDoc.sliceString(from,to).trim())return [];
      return [{from,to}];
    });
    const ranges=mergeRegions(emptied);
    if(!ranges.length)return tr;
    const changes=ChangeSet.of(ranges,tr.newDoc.length),doc=changes.apply(tr.newDoc);
    const selection=EditorSelection.create(tr.newSelection.ranges.map(range=>{
      if(!range.empty||!ranges.some(r=>range.from>=r.from&&range.from<=r.to))return range.map(changes);
      const position=changes.mapPos(range.from),line=doc.lineAt(position);
      return EditorSelection.cursor(line.from+line.text.search(/\S|$/));
    }),tr.newSelection.mainIndex);
    // Compose with the original edit: one history entry and one autosave notification.
    return [tr,{changes,selection,sequential:true}];
  }),
});

/** Attachment checks for prompt visibility, not a substitute for analysis. */
export function sourcePromptAttachments(source:string, candidates:Candidate[], documentation?:Documentation, syntax=rustLanguage.parser.parse(source)) {
  return candidates.map(candidate=>{
    const position=candidate.position;
    // Attributes wrap their item, but never an operation inside its body.
    let anchor=position;
    for(let node=syntax.resolveInner(position,1);node.parent;node=node.parent){
      if(node.from===position && node.parent.name==='AttributeItem')anchor=node.parent.from;
    }
    const lineStart=source.lastIndexOf('\n',anchor-1)+1;
    const prefix=source.slice(source.lastIndexOf('\n',position-1)+1,position).trim();
    // Markers attach by source line, including an operation directly inside unsafe { ... }.
    const insertable=!prefix || (candidate.action==='justification' && /^unsafe\s*\{\s*$/.test(prefix));
    let attached=false,commentStart:number|undefined,markerStart:number|undefined;
    if(!candidate.external && documentation){
      let end=lineStart;
      while(end>0){
        const start=source.lastIndexOf('\n',end-2)+1;
        const line=source.slice(start,end-1).trim();
        const contentStart=start+source.slice(start,end-1).search(/\S/);
        const node=syntax.resolveInner(contentStart,1);
        // A comment-looking line inside a raw string is not documentation.
        if(node.name!=='LineComment' || node.from!==contentStart)break;
        commentStart=start;
        if(candidate.action==='justification' && !line.startsWith('///') && !line.startsWith('//!')){
          const marker=documentation.justification.trim().replace(/:$/, '');
          const text=line.slice(2).trimStart();
          const suffix=text.slice(marker.length).trimStart();
          const matches=!!marker && text.startsWith(marker) && (!suffix || suffix.startsWith(':'));
          if(matches)markerStart=start;
          attached ||= matches;
        }else if(candidate.action==='obligation'){
          const heading=documentation.obligation.replace(/^#\s*/, '').trim();
          attached ||= !!heading && line.startsWith('///') && line.slice(3).trim()===`# ${heading}`;
        }
        end=start;
      }
    }
    return {lineStart,insertable,attached,commentStart,markerStart};
  });
}
