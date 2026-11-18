/* Le relais: the public shell contains no class preparation or password. */
const MANIFEST_AAD = 'relais-cm1:v1:manifest';
const STORAGE_KEY = 'relais-cm1.access.v1';
const TYPES = {pdf:'application/pdf',pptx:'application/vnd.openxmlformats-officedocument.presentationml.presentation',zip:'application/zip',mp3:'audio/mpeg',png:'image/png',jpg:'image/jpeg',jpeg:'image/jpeg'};
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', {fatal:true});
const MAX_ASSET = 150 * 1024 * 1024;
const MAX_MANIFEST = 8 * 1024 * 1024;
const isRecord = value => value && typeof value === 'object' && !Array.isArray(value);
const isText = (value, max=5000) => typeof value === 'string' && value.length <= max;
const isLines = value => Array.isArray(value) && value.length <= 100 && value.every(v=>isText(v));
const isId = value => typeof value === 'string' && /^[a-zA-Z0-9_-]{1,100}$/.test(value);
const hex = bytes => Array.from(new Uint8Array(bytes), b=>b.toString(16).padStart(2,'0')).join('');

export function validDate(value) {
  return typeof value === 'string' && /^20\d{2}-\d{2}-\d{2}$/.test(value) && Number.isFinite(Date.parse(value+'T12:00:00Z')) && new Date(value+'T12:00:00Z').toISOString().slice(0,10)===value;
}
export function safeAssetURL(path, base=globalThis.location?.href) {
  if (typeof path !== 'string' || !/^data\/[a-f0-9]{64}\.bin$/.test(path)) throw new Error('Adresse de document invalide.');
  const root = new URL('./', base);
  const url = new URL(path, root);
  if (url.origin !== root.origin || !url.pathname.startsWith(root.pathname+'data/')) throw new Error('Adresse de document invalide.');
  return url.href;
}
export function fromBase64(value, expectedLength) {
  if (typeof value !== 'string' || value.length > 200 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) throw new Error('Paramètres de protection invalides.');
  let bytes;
  try { bytes = Uint8Array.from(atob(value), c=>c.charCodeAt(0)); } catch { throw new Error('Paramètres de protection invalides.'); }
  if (expectedLength && bytes.length !== expectedLength) throw new Error('Paramètres de protection invalides.');
  return bytes;
}
const toBase64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
export function parseVaultDescriptor(value) {
  if (!isRecord(value) || value.format !== 'relais-cm1-vault' || value.version !== 1 || !isRecord(value.kdf) || !isRecord(value.cipher) || !isRecord(value.manifest)) throw new Error('Le dossier de la classe est indisponible.');
  const {kdf,cipher,manifest}=value;
  if (kdf.name!=='PBKDF2' || kdf.hash!=='SHA-256' || !Number.isInteger(kdf.iterations) || kdf.iterations<100000 || kdf.iterations>2000000 || cipher.name!=='AES-GCM' || cipher.keyBits!==256 || cipher.tagBits!==128) throw new Error('Format de protection non reconnu.');
  fromBase64(kdf.salt,16); fromBase64(manifest.iv,12);
  if (!Number.isInteger(manifest.sizeBytes) || manifest.sizeBytes<17 || manifest.sizeBytes>MAX_MANIFEST || !/^data\/[a-f0-9]{64}\.bin$/.test(manifest.path)) throw new Error('Le dossier de la classe est invalide.');
  return value;
}
export async function deriveVaultKey(password, descriptor, extractable=false) {
  const d=parseVaultDescriptor(descriptor);
  const material=await crypto.subtle.importKey('raw',encoder.encode(password.normalize('NFC')),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt:fromBase64(d.kdf.salt,16),iterations:d.kdf.iterations},material,{name:'AES-GCM',length:256},extractable,['decrypt']);
}
export async function decryptPayload(key, ciphertext, iv, aad) {
  return crypto.subtle.decrypt({name:'AES-GCM',iv:fromBase64(iv,12),additionalData:encoder.encode(aad),tagLength:128},key,ciphertext);
}
export function parseManifest(value) {
  if (!isRecord(value) || value.version!==1 || !validDate(value.latestDate) || !isRecord(value.days) || !isRecord(value.assets) || !isText(value.updatedAt,60)) throw new Error('Le programme est invalide.');
  const dates=Object.keys(value.days), assetEntries=Object.entries(value.assets);
  if (!dates.length || dates.length>370 || assetEntries.length>10000 || !value.days[value.latestDate]) throw new Error('Le programme est invalide.');
  for (const [path,a] of assetEntries) {
    if (!isRecord(a) || !/^[a-f0-9]{32}$/.test(a.id) || !/^data\/[a-f0-9]{64}\.bin$/.test(a.path) || !isText(a.filename,240) || !Number.isInteger(a.sizeBytes) || a.sizeBytes<1 || a.sizeBytes>MAX_ASSET || a.cipherSizeBytes!==a.sizeBytes+16 || !/^[a-f0-9]{64}$/.test(a.sha256)) throw new Error('Un document est invalide.');
    fromBase64(a.iv,12);
    const ext=path.split('.').pop()?.toLowerCase();
    if (!TYPES[ext] || a.mime!==TYPES[ext] || /[\x00-\x1f]/.test(path)) throw new Error('Un document est invalide.');
  }
  for (const date of dates) {
    const d=value.days[date];
    if (!validDate(date) || !isRecord(d) || d.date!==date || !isText(d.title,250) || !isText(d.intro) || !Number.isFinite(Date.parse(d.updatedAt)) || !['ready','partial','missing'].includes(d.status) || !isLines(d.notes) || !isLines(d.missing) || !Array.isArray(d.documents) || d.documents.length>100 || !Array.isArray(d.sessions) || d.sessions.length>60) throw new Error('Une journée est invalide.');
    const ids=new Set();
    for (const doc of d.documents) {
      const a=isRecord(doc)&&typeof doc.path==='string'&&Object.prototype.hasOwnProperty.call(value.assets,doc.path)?value.assets[doc.path]:null;
      if (!isRecord(doc) || !isId(doc.id) || ids.has(doc.id) || !isText(doc.title,250) || !['slides','journal','worksheet','correction','other'].includes(doc.kind) || !a || doc.mime!==a.mime || doc.sizeBytes!==a.sizeBytes || (doc.sha256 && doc.sha256!==a.sha256) || (doc.subject!==undefined&&!isText(doc.subject,200)) || (doc.printInstructions!==undefined&&!isText(doc.printInstructions))) throw new Error('Un document de la journée est invalide.');
      ids.add(doc.id);
    }
    const sessionIds=new Set();
    for (const s of d.sessions) {
      if (!isRecord(s) || !isId(s.id) || sessionIds.has(s.id) || !isText(s.title,250) || !isText(s.subject,200) || (s.time!==undefined&&!isText(s.time,200)) || (s.objective!==undefined&&!isText(s.objective)) || !isLines(s.instructions) || !isLines(s.materials) || !Array.isArray(s.documentIds) || !s.documentIds.every(id=>ids.has(id))) throw new Error('Une séance est invalide.');
      sessionIds.add(s.id);
    }
  }
  return value;
}
export const parisDate = (now=new Date()) => {const parts=new Intl.DateTimeFormat('en-CA',{timeZone:'Europe/Paris',year:'numeric',month:'2-digit',day:'2-digit'}).formatToParts(now);return ['year','month','day'].map(type=>parts.find(p=>p.type===type).value).join('-');};
export function rememberExpiry(now=Date.now()) {
  const today=parisDate(new Date(now));
  let low=now,high=now+27*60*60*1000;
  while (high-low>1000) { const middle=Math.floor((low+high)/2); if(parisDate(new Date(middle))===today)low=middle;else high=middle; }
  return high;
}
const keyFingerprint = descriptor => `${descriptor.kdf.name}:${descriptor.kdf.hash}:${descriptor.kdf.iterations}:${descriptor.kdf.salt}`;
const sizeLabel = n=>n>=1048576?`${(n/1048576).toFixed(1).replace('.',',')} Mo`:`${Math.max(1,Math.round(n/1024))} Ko`;
const dateLabel = date=>new Intl.DateTimeFormat('fr-FR',{weekday:'long',day:'numeric',month:'long',year:'numeric',timeZone:'Europe/Paris'}).format(new Date(date+'T12:00:00Z'));
const safeFilename = filename=>filename.replace(/[\\/\x00-\x1f<>:"|?*]/g,'-').slice(0,180)||'document';

async function fetchBytes(path, size, maximum) {
  const response=await fetch(safeAssetURL(path),{cache:'no-store',credentials:'omit',redirect:'error'});
  if (!response.ok) throw new Error('Le document ne peut pas être chargé. Vérifiez la connexion puis réessayez.');
  const declared=Number(response.headers.get('Content-Length')||0);
  if (declared>maximum) throw new Error('Le document dépasse la taille prévue.');
  const data=await response.arrayBuffer();
  if (data.byteLength!==size || data.byteLength>maximum) throw new Error('Le fichier reçu est incomplet. Réessayez.');
  const expected=path.match(/([a-f0-9]{64})\.bin$/)[1];
  if (hex(await crypto.subtle.digest('SHA-256',data))!==expected) throw new Error('Le fichier reçu ne correspond pas au document attendu.');
  return data;
}
async function fetchDescriptor() {
  const response=await fetch(new URL('./vault.json',location.href),{cache:'no-store',credentials:'omit',redirect:'error'});
  if (!response.ok) throw new Error('La préparation ne peut pas être chargée. Vérifiez la connexion puis réessayez.');
  const raw=await response.text();
  if(raw.length>20000)throw new Error('Le dossier de la classe est invalide.');
  return parseVaultDescriptor(JSON.parse(raw));
}
async function openManifest(key, descriptor) {
  const m=descriptor.manifest;
  const bytes=await fetchBytes(m.path,m.sizeBytes,MAX_MANIFEST);
  return parseManifest(JSON.parse(decoder.decode(await decryptPayload(key,bytes,m.iv,MANIFEST_AAD))));
}

function startUI() {
  const $=id=>document.getElementById(id);
  const el=(tag,className,text)=>{const node=document.createElement(tag);if(className)node.className=className;if(text!==undefined)node.textContent=text;return node;};
  const button=(text,className,handler)=>{const node=el('button',className,text);node.type='button';node.addEventListener('click',handler);return node;};
  const append=(parent,...children)=>{for(const child of children.flat())if(child)parent.append(child);return parent;};
  const icon=(type,size=18)=>{
    const paths={book:'M3 4c4-1 7 0 9 2 3-2 6-3 9-2v15c-4-1-7 0-9 2-3-2-6-3-9-2zM12 6v15',file:'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M8 13h8M8 17h6',download:'M12 3v12m-5-5 5 5 5-5M5 16v5h14v-5',clock:'M12 8v5l3 2M22 12a10 10 0 1 1-20 0 10 10 0 0 1 20 0',print:'M6 9V3h12v6M6 17H3V9h18v8h-3M6 14h12v7H6z',screen:'M3 3h18v13H3zM12 16v5M7 21h10M10 7l5 3-5 3z',calendar:'M3 5h18v16H3zM7 2v6M17 2v6M3 10h18',check:'m5 12 4 4L19 6',refresh:'M20 7a9 9 0 1 0 1 9M20 3v5h-5',alert:'m12 3 10 18H2zM12 9v5m0 3v1',arrow:'M5 12h14m-5-5 5 5-5 5'};
    const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');svg.setAttribute('viewBox','0 0 24 24');svg.setAttribute('width',size);svg.setAttribute('height',size);svg.setAttribute('fill','none');svg.setAttribute('stroke','currentColor');svg.setAttribute('stroke-width','1.7');svg.setAttribute('stroke-linecap','round');svg.setAttribute('stroke-linejoin','round');svg.setAttribute('aria-hidden','true');const p=document.createElementNS(svg.namespaceURI,'path');p.setAttribute('d',paths[type]||paths.file);svg.append(p);return svg;
  };
  const state={key:null,descriptor:null,manifest:null,selected:'',followingLatest:true,tab:'worksheet',checked:new Set(),generation:0,refreshing:false,cache:new Map(),cacheSize:0,rememberUntil:0,documentId:''};
  const status=(text,error=false)=>{$('login-status').textContent=text;$('login-status').classList.toggle('is-error',error);};
  const clearRemembered=()=>{try{localStorage.removeItem(STORAGE_KEY);}catch{}};
  const deepLink=()=>{const params=new URLSearchParams(location.hash.slice(1));return{date:validDate(params.get('date'))?params.get('date'):'',document:isId(params.get('document'))?params.get('document'):''};};
  function setHash(date,documentId='') {const p=new URLSearchParams();if(date)p.set('date',date);if(documentId)p.set('document',documentId);const hash=p.toString();history.replaceState(null,'',location.pathname+location.search+(hash?'#'+hash:''));}
  function closeDocument() {if($('document-dialog').open)$('document-dialog').close();$('document-dialog').classList.remove('fallback-open');$('document-body').replaceChildren();state.documentId='';if(state.manifest)setHash(state.selected||state.manifest.latestDate);}
  function lock(message='') {
    state.generation++;closeDocument();state.key=null;state.descriptor=null;state.manifest=null;state.selected='';state.checked.clear();state.rememberUntil=0;
    for(const item of state.cache.values())URL.revokeObjectURL(item.url);state.cache.clear();state.cacheSize=0;
    clearRemembered();$('classroom').replaceChildren();$('classroom').hidden=true;$('access-panel').hidden=false;$('lock-button').hidden=true;$('password').value='';$('password').type='password';$('show-password').textContent='Afficher';$('show-password').setAttribute('aria-pressed','false');$('show-password').setAttribute('aria-label','Afficher le mot de passe');$('remember-access').checked=false;status(message);$('password').focus();
  }
  async function remember(key,descriptor) {
    const expiresAt=rememberExpiry();const raw=await crypto.subtle.exportKey('raw',key);
    try {localStorage.setItem(STORAGE_KEY,JSON.stringify({version:1,key:toBase64(raw),expiresAt,date:parisDate(),fingerprint:keyFingerprint(descriptor)}));state.rememberUntil=expiresAt;}catch{status('Accès ouvert. Cet appareil ne permet pas de le garder en mémoire.');}
  }
  function reveal(manifest,descriptor,key) {
    state.manifest=manifest;state.descriptor=descriptor;state.key=key;state.selected=deepLink().date||manifest.latestDate;state.followingLatest=!deepLink().date;
    $('password').value='';$('access-panel').hidden=true;$('classroom').hidden=false;$('lock-button').hidden=false;render();
    const link=deepLink();if(link.document)void showDocument(link.document);
  }
  async function unlock(event) {
    event.preventDefault();const password=$('password').value;if(!password)return;
    const shouldRemember=$('remember-access').checked, generation=++state.generation;$('unlock-button').disabled=true;status('Ouverture de la journée…');
    try {
      if(!crypto?.subtle)throw new Error('Ouvrez cette adresse en HTTPS dans un navigateur récent.');
      const descriptor=await fetchDescriptor();const key=await deriveVaultKey(password,descriptor,shouldRemember);
      let manifest;try{manifest=await openManifest(key,descriptor);}catch(error){if(error.name==='OperationError')throw new Error('Le mot de passe ne convient pas. Vérifiez-le puis réessayez.');throw error;}
      if(generation!==state.generation)return;
      clearRemembered();if(shouldRemember)await remember(key,descriptor);reveal(manifest,descriptor,key);status('');
    } catch(error) {if(generation===state.generation)status(error.message||'Impossible d’ouvrir la journée. Réessayez.',true);}
    finally {$('unlock-button').disabled=false;}
  }
  async function restore() {
    let saved;try{saved=JSON.parse(localStorage.getItem(STORAGE_KEY)||'null');}catch{clearRemembered();return;}
    if(!saved)return;
    if(saved.version!==1 || !Number.isFinite(saved.expiresAt) || saved.expiresAt<=Date.now() || saved.date!==parisDate() || saved.expiresAt>rememberExpiry()+1000){clearRemembered();return;}
    const generation=++state.generation;status('Réouverture de la journée…');$('unlock-button').disabled=true;
    try {
      const descriptor=await fetchDescriptor();if(saved.fingerprint!==keyFingerprint(descriptor))throw new Error('Le mot de passe a changé. Entrez le nouveau mot de passe.');
      const key=await crypto.subtle.importKey('raw',fromBase64(saved.key,32),{name:'AES-GCM'},false,['decrypt']);
      const manifest=await openManifest(key,descriptor);if(generation!==state.generation)return;
      state.rememberUntil=saved.expiresAt;reveal(manifest,descriptor,key);status('');
    } catch {clearRemembered();status('Entrez le mot de passe pour ouvrir la journée.');}
    finally {$('unlock-button').disabled=false;}
  }
  async function refresh(latest=false) {
    if(!state.key || state.refreshing)return;state.refreshing=true;const generation=state.generation;
    try {
      const descriptor=await fetchDescriptor();if(generation!==state.generation)return;
      if(keyFingerprint(descriptor)!==keyFingerprint(state.descriptor)){lock('Le mot de passe a changé. Entrez le nouveau mot de passe.');return;}
      const changed=descriptor.manifest.path!==state.descriptor.manifest.path;
      if(changed){const manifest=await openManifest(state.key,descriptor);if(generation!==state.generation)return;state.manifest=manifest;state.descriptor=descriptor;if(state.followingLatest){if(state.selected!==manifest.latestDate){closeDocument();state.checked.clear();}state.selected=manifest.latestDate;}}
      if(latest){state.selected=state.manifest.latestDate;state.followingLatest=true;setHash(state.selected);state.checked.clear();}
      if(changed||latest)render();
    } catch(error) {const target=$('refresh-status');if(target)target.textContent='La mise à jour n’a pas pu être vérifiée. Le dernier contenu chargé reste affiché.';}
    finally {state.refreshing=false;}
  }
  const documentCard=doc=>{
    const node=button('','document-link',()=>void showDocument(doc.id));const label=el('span','',doc.title);
    label.append(el('small','',`${doc.pages?doc.pages+' page'+(doc.pages>1?'s':'')+' · ':''}${doc.path.split('.').pop().toUpperCase()} · ${sizeLabel(doc.sizeBytes)}`));
    return append(node,icon('file'),label,icon('download',17));
  };
  function render() {
    if(!state.manifest)return;const root=$('classroom');root.replaceChildren();const d=state.manifest.days[state.selected];
    root.append(append(el('p','eyebrow'),el('span'),document.createTextNode('ESPACE REMPLAÇANT')));
    const welcome=el('section','welcome'),copy=el('div'),h=el('h1');append(h,document.createTextNode('Tout pour prendre'),el('br'),el('span','','le relais.'));append(copy,h,el('p','','Le fil de la journée et les supports utiles, réunis au même endroit. Bonne journée en CM1 !'));
    const drawing=el('div','welcome-drawing');drawing.setAttribute('aria-hidden','true');const paper=el('div','paper paper-front');append(paper,el('span','paper-tag','CM1'),el('div','paper-line'),el('div','paper-line short'),append(el('div','paper-check'),icon('check'),el('span','','C’est parti !')));append(drawing,el('div','paper paper-back'),paper,el('span','spark','✳'));root.append(append(welcome,copy,drawing));
    const nav=el('nav','section-nav');nav.setAttribute('aria-label','Accès rapide');for(const [id,label,glyph] of [['journee','La journée','calendar'],['diaporama','Diaporama','screen'],['photocopies','Photocopies','print']]){const a=el('a','',label);a.href='#'+id;a.prepend(icon(glyph,17));a.addEventListener('click',e=>{e.preventDefault();document.getElementById(id)?.scrollIntoView({behavior:matchMedia('(prefers-reduced-motion:reduce)').matches?'auto':'smooth'});});nav.append(a);}root.append(nav);
    const heading=el('section','day-heading');heading.id='journee';const title=append(el('div'),el('p','eyebrow text-muted','LA JOURNÉE PRÉPARÉE'),el('h2','',d?dateLabel(d.date):'Le programme de la classe'));
    if(d){const date=new Intl.DateTimeFormat('fr-FR',{day:'numeric',month:'long',hour:'2-digit',minute:'2-digit',timeZone:'Europe/Paris'}).format(new Date(d.updatedAt));title.append(append(el('p','updated'),icon('clock',13),document.createTextNode('Mis à jour le '+date)));}
    const input=el('input');input.type='date';input.value=state.selected;input.setAttribute('aria-label','Consulter une autre date');input.addEventListener('change',()=>{if(!validDate(input.value))return;state.selected=input.value;state.followingLatest=false;state.checked.clear();setHash(input.value);render();});
    const refreshButton=button('','icon-button',()=>void refresh(true));refreshButton.setAttribute('aria-label','Afficher la dernière préparation');refreshButton.title='Dernière préparation';refreshButton.append(icon('refresh'));
    const dateLabelNode=append(el('label','date-label'),icon('calendar',16),input);append(heading,title,append(el('div','date-actions'),dateLabelNode,refreshButton));root.append(heading);
    const refreshStatus=el('p','refresh-status');refreshStatus.id='refresh-status';refreshStatus.setAttribute('role','status');root.append(refreshStatus);
    if(!d){root.append(append(el('div','alert'),icon('alert',20),append(el('div'),el('strong','','Aucune préparation disponible pour cette date.'),el('p','','Choisissez une autre date ou affichez la dernière préparation.'),button('Dernière préparation','text-button',()=>{state.selected=state.manifest.latestDate;state.followingLatest=true;setHash(state.selected);render();}))));return;}
    const stale=d.date<parisDate();if(stale||d.status!=='ready'){const body=append(el('div'),el('strong','',stale?'Cette préparation concerne une date passée.':d.status==='missing'?'La préparation est à venir.':'Une partie de la journée est prête.'),el('p','',d.intro));if(d.missing.length){const list=el('ul');for(const line of d.missing)list.append(el('li','',line));body.append(list);}root.append(append(el('div','alert'),icon('alert',20),body));}else root.append(append(el('p','ready-note'),icon('check'),document.createTextNode(d.intro||'La journée et ses supports sont prêts.')));
    const slides=d.documents.filter(x=>x.kind==='slides'),pack=d.documents.find(x=>x.path.toLowerCase().endsWith('.zip'));
    const feature=(kind,eyebrow,title,description,glyph)=>{const card=el('section',`feature-card ${kind}-card`);append(card,append(el('div','feature-icon'),icon(glyph,25)),append(el('div','feature-copy'),el('p','eyebrow',eyebrow),el('h3','',title),el('p','',description)));return card;};
    const slideCard=feature('slides','À PROJETER','Le diaporama',slides.length?'Les supports de la journée, prêts à ouvrir sur l’ordinateur de la classe.':'Le diaporama sera ajouté dès qu’il sera préparé.','screen');slideCard.id='diaporama';if(slides.length){const links=el('div','slide-links');for(const doc of slides)links.append(append(button(doc.path.endsWith('.pdf')?'Ouvrir le PDF':'Télécharger le diaporama','button primary',()=>void showDocument(doc.id)),icon('download',17)));slideCard.append(links);}else slideCard.append(el('span','waiting','À venir'));
    const packCard=feature('pack','À GARDER SOUS LA MAIN','Le dossier du jour',pack?'Les fichiers regroupés pour les garder sur votre ordinateur.':'Les documents disponibles sont accessibles ci-dessous.','download');if(pack)packCard.append(append(button('Tout télécharger','button secondary',()=>void showDocument(pack.id)),icon('download',17)));root.append(append(el('div','top-cards'),slideCard,packCard));
    const journal=el('section','journal'),printButton=append(button('Imprimer','small-button',()=>window.print()),icon('print',16));append(journal,append(el('div','section-title'),append(el('div'),el('p','eyebrow text-muted','LE FIL CONDUCTEUR'),el('h3','','Cahier journal')),printButton));const timeline=el('div','timeline');
    d.sessions.forEach((s,i)=>{const article=el('article','session'),content=el('div','session-content'),meta=append(el('div','session-meta'),el('span','',s.subject));if(s.time)meta.append(append(el('span'),icon('clock',13),document.createTextNode(s.time)));append(content,meta,el('h4','',s.title));if(s.objective)content.append(el('p','objective',s.objective));const list=el('ol','steps');for(const line of s.instructions)list.append(el('li','',line));content.append(list);if(s.materials.length)content.append(append(el('p','materials'),el('strong','','Matériel'),document.createTextNode(' '+s.materials.join(' · '))));const links=el('div','session-documents');for(const id of s.documentIds){const doc=d.documents.find(x=>x.id===id);if(doc)links.append(documentCard(doc));}content.append(links);append(article,append(el('div','session-rail'),el('span','',String(i+1).padStart(2,'0'))),content);timeline.append(article);});journal.append(timeline);if(!d.sessions.length)journal.append(el('p','empty','Le déroulé sera ajouté dès qu’il sera préparé.'));
    const aside=el('aside','side-column'),panel=el('section','print-panel');panel.id='photocopies';append(panel,append(el('div','section-title'),append(el('div'),el('p','eyebrow text-muted','LES SUPPORTS'),el('h3','','Photocopies')),icon('print',23)));
    const tabs=el('div','tabs');tabs.setAttribute('role','tablist');tabs.setAttribute('aria-label','Type de documents');for(const [kind,label] of [['worksheet','Élèves'],['correction','Corrigés']]){const tab=button(label,'',()=>{state.tab=kind;render();document.getElementById('photocopies')?.scrollIntoView({block:'nearest'});});tab.setAttribute('role','tab');tab.setAttribute('aria-selected',String(state.tab===kind));tab.append(el('span','',String(d.documents.filter(x=>x.kind===kind).length)));tabs.append(tab);}panel.append(tabs);
    const tabPanel=el('div');tabPanel.setAttribute('role','tabpanel');const printDocs=d.documents.filter(x=>x.kind===state.tab);for(const doc of printDocs){const item=append(el('div','print-item'),el('div','print-subject',doc.subject||'Document'),documentCard(doc));if(doc.copies||doc.printInstructions)item.append(el('p','print-detail',`${doc.copies?doc.copies+' exemplaires'+(doc.printInstructions?' · ':''):''}${doc.printInstructions||''}`));if(state.tab==='worksheet'){const checkbox=el('input');checkbox.type='checkbox';checkbox.checked=state.checked.has(doc.id);checkbox.addEventListener('change',()=>checkbox.checked?state.checked.add(doc.id):state.checked.delete(doc.id));item.append(append(el('label','print-check'),checkbox,document.createTextNode('Photocopies prêtes')));}tabPanel.append(item);}if(!printDocs.length)tabPanel.append(el('p','empty-small','Aucun document publié dans cette rubrique pour le moment.'));panel.append(tabPanel);if(state.tab==='worksheet'&&printDocs.length)panel.append(el('p','check-note','Ces repères restent sur cette page pendant votre préparation.'));aside.append(panel);
    if(d.notes.length){const notes=el('section','notes-panel'),list=el('ul');for(const line of d.notes)list.append(el('li','',line));append(notes,append(el('div','section-title'),el('h3','','Petits repères'),icon('book',20)),list);aside.append(notes);}root.append(append(el('div','content-grid'),journal,aside));
  }
  async function decryptedAsset(doc) {
    const asset=state.manifest.assets[doc.path],generation=state.generation;
    const existing=state.cache.get(asset.path);if(existing)return existing;
    const encrypted=await fetchBytes(asset.path,asset.cipherSizeBytes,MAX_ASSET+16);
    const plain=await decryptPayload(state.key,encrypted,asset.iv,'relais-cm1:v1:asset:'+asset.id);
    if(generation!==state.generation || !state.key)throw new Error('L’accès a été verrouillé.');
    if(plain.byteLength!==asset.sizeBytes || hex(await crypto.subtle.digest('SHA-256',plain))!==asset.sha256)throw new Error('Le document reçu ne correspond pas au fichier attendu.');
    if(generation!==state.generation)throw new Error('L’accès a été verrouillé.');
    if(state.cacheSize+plain.byteLength>80*1024*1024){for(const item of state.cache.values())URL.revokeObjectURL(item.url);state.cache.clear();state.cacheSize=0;}
    const blob=new Blob([plain],{type:asset.mime}),result={url:URL.createObjectURL(blob),filename:safeFilename(asset.filename),mime:asset.mime,sizeBytes:asset.sizeBytes};state.cache.set(asset.path,result);state.cacheSize+=plain.byteLength;return result;
  }
  async function showDocument(id) {
    const day=state.manifest?.days[state.selected];const doc=day?.documents.find(x=>x.id===id);if(!doc)return;
    const generation=state.generation;state.documentId=id;setHash(day.date,id);$('document-title').textContent=doc.title;$('document-body').replaceChildren(el('p','document-preparing','Préparation du fichier…'));
    const dialog=$('document-dialog');if(!dialog.open){if(typeof dialog.showModal==='function')dialog.showModal();else dialog.classList.add('fallback-open');}
    try {
      const item=await decryptedAsset(doc);if(generation!==state.generation || state.documentId!==id)return;
      const body=$('document-body');body.replaceChildren(el('p','document-meta',`${item.filename} · ${sizeLabel(item.sizeBytes)}`));
      if(item.mime.startsWith('audio/')){const audio=el('audio');audio.controls=true;audio.preload='metadata';audio.src=item.url;body.append(audio);}
      const actions=el('div','document-actions');
      if(item.mime==='application/pdf'||item.mime.startsWith('image/')){const open=el('a','button secondary',item.mime==='application/pdf'?'Ouvrir le PDF':'Ouvrir l’image');open.href=item.url;open.target='_blank';open.rel='noopener noreferrer';actions.append(open);}
      // These are real anchors shown AFTER decryption. Their next click retains
      // the user gesture required by Safari/iPad, without opening an async popup.
      const save=append(el('a','button primary','Enregistrer / Télécharger'),icon('download',17));save.href=item.url;save.download=item.filename;actions.append(save);body.append(actions);
      body.append(el('p','download-help','Sur iPad ou iPhone, si le document s’ouvre, utilisez Partager puis « Enregistrer dans Fichiers ».'));
      save.focus();
    } catch(error) {if(generation!==state.generation || state.documentId!==id)return;const body=$('document-body');body.replaceChildren(el('p','document-error',error.message||'Impossible d’ouvrir le document.'),button('Réessayer','button secondary',()=>void showDocument(id)));}
  }
  $('unlock-form').addEventListener('submit',unlock);$('lock-button').addEventListener('click',()=>lock());$('close-document').addEventListener('click',closeDocument);$('document-dialog').addEventListener('cancel',e=>{e.preventDefault();closeDocument();});
  $('show-password').addEventListener('click',()=>{const show=$('password').type==='password';$('password').type=show?'text':'password';$('show-password').textContent=show?'Masquer':'Afficher';$('show-password').setAttribute('aria-pressed',String(show));$('show-password').setAttribute('aria-label',show?'Masquer le mot de passe':'Afficher le mot de passe');});
  window.addEventListener('hashchange',()=>{if(!state.manifest)return;const link=deepLink();if(link.date){state.selected=link.date;state.followingLatest=false;render();}if(link.document)void showDocument(link.document);else closeDocument();});
  window.addEventListener('pagehide',()=>{closeDocument();for(const item of state.cache.values())URL.revokeObjectURL(item.url);state.cache.clear();state.cacheSize=0;});
  setInterval(()=>{if(state.rememberUntil&&Date.now()>=state.rememberUntil){lock('L’accès gardé sur cet appareil a expiré. Entrez à nouveau le mot de passe.');return;}if(!document.hidden)void refresh();},60000);
  document.addEventListener('visibilitychange',()=>{if(!document.hidden){if(state.rememberUntil&&Date.now()>=state.rememberUntil)lock('L’accès gardé sur cet appareil a expiré.');else void refresh();}});
  void restore();
}
if (typeof document !== 'undefined') startUI();
