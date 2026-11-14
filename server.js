const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = Number(process.env.PORT || 3000);
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || 'admin@bhstory.local').toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || ''; 
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const MUSIC_DIR = path.join(__dirname, 'uploads', 'music');
if (!fs.existsSync(MUSIC_DIR)) fs.mkdirSync(MUSIC_DIR, { recursive: true });
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify({ users: [], orders: [], music: [] }, null, 2));
let db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
if (!db.music) db.music = [];
const sessions = new Map();
const online = new Map();
const adminStreams = new Set();
const save = () => fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
const json = (res, status, data) => { res.writeHead(status, { 'Content-Type':'application/json; charset=utf-8', 'Cache-Control':'no-store' }); res.end(JSON.stringify(data)); };
const parseCookies = req => Object.fromEntries((req.headers.cookie || '').split(';').map(x=>x.trim()).filter(Boolean).map(x=>{const i=x.indexOf('=');return [x.slice(0,i),decodeURIComponent(x.slice(i+1))]}));
function cookie(res, name, value, maxAge=60*60*24*7) { res.setHeader('Set-Cookie', `${name}=${encodeURIComponent(value)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${process.env.NODE_ENV==='production'?'; Secure':''}`); }
function readBody(req) { return new Promise((resolve,reject)=>{let b='';req.on('data',c=>{b+=c;if(b.length>1e6)req.destroy()});req.on('end',()=>{try{resolve(b?JSON.parse(b):{})}catch(e){reject(e)}});req.on('error',reject)}); }
function readUpload(req){return new Promise((resolve,reject)=>{const chunks=[];let size=0;req.on('data',c=>{size+=c.length;if(size>15*1024*1024){reject(new Error('Arquivo maior que 15 MB.'));req.destroy();return;}chunks.push(c)});req.on('end',()=>{try{const raw=Buffer.concat(chunks),boundary='--'+(req.headers['content-type']||'').split('boundary=')[1];if(!boundary||!raw.length)throw Error('Envie um arquivo de áudio.');const latin=raw.toString('latin1'),start=latin.indexOf('filename=');if(start<0)throw Error('Arquivo não encontrado.');const headEnd=latin.indexOf('\r\n\r\n',start),end=latin.indexOf('\r\n'+boundary,headEnd),header=latin.slice(0,headEnd),match=header.match(/filename="([^"]+)"/);if(!match||headEnd<0||end<0)throw Error('Upload inválido.');const filename=path.basename(match[1]).replace(/[^a-zA-Z0-9._-]/g,'_'),ext=path.extname(filename).toLowerCase();if(!['.mp3','.ogg','.wav','.m4a'].includes(ext))throw Error('Formato permitido: MP3, OGG, WAV ou M4A.');const data=raw.subarray(Buffer.byteLength(latin.slice(0,headEnd+4),'latin1'),Buffer.byteLength(latin.slice(0,end),'latin1'));resolve({filename,data,ext});}catch(e){reject(e)}});req.on('error',reject)});}
function hash(pw, salt=crypto.randomBytes(16).toString('hex')) { return new Promise((resolve,reject)=>crypto.scrypt(pw,salt,64,(e,key)=>e?reject(e):resolve(`${salt}:${key.toString('hex')}`))); }
function verify(pw, stored) { return new Promise(resolve=>{const [salt,key]=String(stored).split(':');crypto.scrypt(pw,salt,64,(e,derived)=>resolve(!e&&crypto.timingSafeEqual(Buffer.from(key,'hex'),derived)))}); }
function sessionFor(req) { const id=parseCookies(req).bh_session; return id ? sessions.get(id) : null; }
function requireUser(req,res) { const s=sessionFor(req); if(!s||s.role!=='customer'){json(res,401,{error:'Faça login para continuar.'});return null} return s; }
function requireAdmin(req,res) { const s=sessionFor(req); if(!s||s.role!=='admin'){json(res,401,{error:'Acesso administrativo necessário.'});return null} return s; }
function publicUser(u){return {id:u.id,name:u.name,email:u.email,address:u.address,createdAt:u.createdAt};}
function broadcast(event,data){const msg=`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`; for(const r of [...adminStreams]){try{r.write(msg)}catch{adminStreams.delete(r)}}}
function onlineList(){const now=Date.now();for(const [id,v] of online)if(now-v.lastSeen>65000)online.delete(id);return [...online.values()].map(v=>({id:v.userId,name:v.name,email:v.email,lastSeen:v.lastSeen}));}
setInterval(()=>broadcast('presence',{online:onlineList().length,customers:onlineList()}),15000).unref();

const server=http.createServer(async(req,res)=>{
  const u=new URL(req.url,'http://localhost'); const p=u.pathname;
  if(req.method==='GET' && p==='/api/health') return json(res,200,{ok:true});
  if(req.method==='GET' && p==='/api/music') return json(res,200,{music:db.music.map(({id,name,url})=>({id,name,url}))});
  if(req.method==='POST' && p==='/api/register'){
    try{const b=await readBody(req);const name=String(b.name||'').trim(),email=String(b.email||'').trim().toLowerCase(),password=String(b.password||''),address={street:String(b.street||'').trim(),number:String(b.number||'').trim(),complement:String(b.complement||'').trim(),district:String(b.district||'').trim(),city:String(b.city||'').trim(),state:String(b.state||'').trim(),zip:String(b.zip||'').trim()};
      if(name.length<2||!/^\S+@\S+\.\S+$/.test(email)||password.length<8||!address.street||!address.number||!address.city||!address.state||!address.zip) return json(res,400,{error:'Preencha os campos obrigatórios. A senha precisa ter pelo menos 8 caracteres.'});
      if(db.users.some(x=>x.email===email))return json(res,409,{error:'Este e-mail já possui cadastro.'});
      const user={id:crypto.randomUUID(),name,email,passwordHash:await hash(password),address,createdAt:new Date().toISOString()};db.users.push(user);save();const sid=crypto.randomBytes(32).toString('hex');sessions.set(sid,{role:'customer',userId:user.id});cookie(res,'bh_session',sid);return json(res,201,{user:publicUser(user)});
    }catch{return json(res,400,{error:'Não foi possível concluir o cadastro.'})}
  }
  if(req.method==='POST' && p==='/api/login'){
    try{const b=await readBody(req),email=String(b.email||'').trim().toLowerCase(),pw=String(b.password||'');const user=db.users.find(x=>x.email===email);if(!user||!await verify(pw,user.passwordHash))return json(res,401,{error:'E-mail ou senha incorretos.'});const sid=crypto.randomBytes(32).toString('hex');sessions.set(sid,{role:'customer',userId:user.id});cookie(res,'bh_session',sid);return json(res,200,{user:publicUser(user)});}catch{return json(res,400,{error:'Dados inválidos.'})}
  }
  if(req.method==='POST' && p==='/api/admin/login'){
    try{const b=await readBody(req);if(!ADMIN_PASSWORD)return json(res,503,{error:'Configure ADMIN_PASSWORD nas variáveis do servidor antes de acessar o painel.'});if(String(b.email||'').toLowerCase()!==ADMIN_EMAIL||String(b.password||'')!==ADMIN_PASSWORD)return json(res,401,{error:'Credenciais administrativas incorretas.'});const sid=crypto.randomBytes(32).toString('hex');sessions.set(sid,{role:'admin'});cookie(res,'bh_session',sid);return json(res,200,{ok:true});}catch{return json(res,400,{error:'Dados inválidos.'})}
  }
  if(req.method==='POST' && p==='/api/logout'){const c=parseCookies(req),sid=c.bh_session;if(sid){sessions.delete(sid);online.delete(sid)}cookie(res,'bh_session','',0);return json(res,200,{ok:true});}
  if(req.method==='GET' && p==='/api/me'){const s=sessionFor(req);if(!s||s.role!=='customer')return json(res,200,{user:null});const user=db.users.find(x=>x.id===s.userId);return json(res,200,{user:user?publicUser(user):null});}
  if(req.method==='POST' && p==='/api/heartbeat'){const s=requireUser(req,res);if(!s)return;const user=db.users.find(x=>x.id===s.userId);if(user){const sid=parseCookies(req).bh_session;online.set(sid,{userId:user.id,name:user.name,email:user.email,lastSeen:Date.now()});}return json(res,200,{ok:true});}
  if(req.method==='POST' && p==='/api/orders'){
    const s=requireUser(req,res);if(!s)return;try{const b=await readBody(req),items=Array.isArray(b.items)?b.items:[];if(!items.length)return json(res,400,{error:'Carrinho vazio.'});const user=db.users.find(x=>x.id===s.userId);if(!user)return json(res,401,{error:'Faça login novamente.'});const clean=items.map(x=>({name:String(x.name||'Produto').slice(0,100),quantity:Math.max(1,Math.min(99,Number(x.quantity)||1)),price:Math.max(0,Number(x.price)||0)}));const total=clean.reduce((a,x)=>a+x.quantity*x.price,0);const order={id:'BH-'+Date.now().toString().slice(-8),userId:user.id,customerName:user.name,email:user.email,address:user.address,items:clean,total,status:'Recebido',createdAt:new Date().toISOString()};db.orders.unshift(order);save();broadcast('order',order);return json(res,201,{order:{id:order.id,status:order.status,total:order.total}});}catch{return json(res,400,{error:'Não foi possível registrar o pedido.'})}
  }
  if(req.method==='GET' && p==='/api/my-orders'){const s=requireUser(req,res);if(!s)return;return json(res,200,{orders:db.orders.filter(o=>o.userId===s.userId)});}
  if(req.method==='GET' && p==='/api/admin/data'){if(!requireAdmin(req,res))return;return json(res,200,{customers:db.users.map(publicUser),orders:db.orders,online:onlineList()});}
  if(req.method==='GET' && p==='/api/admin/music'){if(!requireAdmin(req,res))return;return json(res,200,{music:db.music});}
  if(req.method==='POST' && p==='/api/admin/music'){if(!requireAdmin(req,res))return;try{const f=await readUpload(req),stored=crypto.randomUUID()+f.ext;fs.writeFileSync(path.join(MUSIC_DIR,stored),f.data);const item={id:crypto.randomUUID(),name:f.filename,url:'/media/music/'+stored,createdAt:new Date().toISOString()};db.music.unshift(item);save();return json(res,201,{music:item});}catch(e){return json(res,400,{error:e.message||'Falha no envio.'})}}
  if(req.method==='DELETE' && p.startsWith('/api/admin/music/')){if(!requireAdmin(req,res))return;const id=p.split('/').pop(),i=db.music.findIndex(x=>x.id===id);if(i<0)return json(res,404,{error:'Música não encontrada.'});const item=db.music.splice(i,1)[0];try{fs.unlinkSync(path.join(MUSIC_DIR,path.basename(item.url)))}catch{}save();return json(res,200,{ok:true});}
  if(req.method==='GET' && p.startsWith('/media/music/')){const file=path.basename(p),target=path.join(MUSIC_DIR,file);if(!fs.existsSync(target))return json(res,404,{error:'Arquivo não encontrado.'});const types={'.mp3':'audio/mpeg','.ogg':'audio/ogg','.wav':'audio/wav','.m4a':'audio/mp4'};res.writeHead(200,{'Content-Type':types[path.extname(file)]||'application/octet-stream','Cache-Control':'public, max-age=3600'});return fs.createReadStream(target).pipe(res);}

  if(req.method==='POST' && p.startsWith('/api/admin/order/')){if(!requireAdmin(req,res))return;try{const id=p.split('/').pop(),b=await readBody(req),order=db.orders.find(x=>x.id===id);if(!order)return json(res,404,{error:'Pedido não encontrado.'});order.status=String(b.status||'Em preparação').slice(0,40);save();broadcast('order-update',order);return json(res,200,{order});}catch{return json(res,400,{error:'Atualização inválida.'})}}
  if(req.method==='GET' && p==='/api/admin/events'){if(!requireAdmin(req,res))return;res.writeHead(200,{'Content-Type':'text/event-stream','Cache-Control':'no-cache','Connection':'keep-alive','X-Accel-Buffering':'no'});res.write('event: connected\ndata: {}\n\n');adminStreams.add(res);req.on('close',()=>adminStreams.delete(res));return;}
  if(req.method==='POST' && p==='/api/monica'){
    try{const b=await readBody(req),msg=String(b.message||'').toLowerCase();let answer='Posso ajudar com produtos, pedidos, cadastro e entregas. O que você gostaria de saber? 💜';if(/oi|olá|ola|bom dia|boa tarde|boa noite/.test(msg))answer='Olá! Seja bem-vindo(a) à BH Story! 💜 Eu sou a Monica, sua atendente virtual. Como posso ajudar?';else if(/pedido|compra|acompanhar/.test(msg))answer='Para consultar seu pedido, entre na sua conta e acesse “Meus pedidos”. Se precisar, posso encaminhar você para nossa equipe humana.';else if(/entrega|frete|prazo/.test(msg))answer='O prazo e o valor da entrega dependem do endereço e serão confirmados pela equipe antes da finalização do pedido.';else if(/produto|preço|preco|valor|estoque/.test(msg))answer='Você pode encontrar os produtos e preços na vitrine da loja. Se me disser o que procura, ajudo a localizar!';else if(/humano|pessoa|atendente/.test(msg))answer='Claro! Vou sinalizar que você deseja falar com uma pessoa da equipe. 💜';else if(/obrigad/.test(msg))answer='Por nada! A BH Story agradece sua visita. 💜';return json(res,200,{name:'Monica',answer});}catch{return json(res,400,{error:'Mensagem inválida.'})}
  }
  if(req.method==='POST' && p==='/api/suporte'){try{const b=await readBody(req),msg=String(b.message||'').toLowerCase();let answer='Sou o Suporte BH Story. Posso orientar sobre acesso à conta, pedidos, pagamentos e entregas. Conte um pouco mais do que aconteceu.';if(/senha|login|entrar|acesso/.test(msg))answer='Confira seu e-mail e senha. Se esqueceu a senha, fale com a equipe para receber ajuda segura. Nunca envie sua senha pelo chat.';else if(/pagamento|pix|cartão|cartao/.test(msg))answer='Posso orientar sobre dúvidas de pagamento. Não envie número completo de cartão, código de segurança ou senhas por aqui.';else if(/pedido|compra/.test(msg))answer='Entre em Minha conta e consulte Meus pedidos. Se não aparecer, informe apenas o número do pedido à equipe.';else if(/entrega|endereço|endereco|frete/.test(msg))answer='Confira o endereço cadastrado em Minha conta. Para corrigir uma entrega solicitada, fale com nossa equipe informando o número do pedido.';else if(/humano|pessoa|atendente/.test(msg))answer='Claro! Entre em contato com a equipe BH Story pelo telefone informado no site.';return json(res,200,{name:'Suporte BH Story',answer});}catch{return json(res,400,{error:'Mensagem inválida.'})}}
  if(req.method==='GET' && (p==='/'||p==='/index.html')){res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});return fs.createReadStream(path.join(__dirname,'index.html')).pipe(res);}
  if(req.method==='GET' && p==='/styles.css'){res.writeHead(200,{'Content-Type':'text/css'});return fs.createReadStream(path.join(__dirname,'styles.css')).pipe(res);}
  res.writeHead(404,{'Content-Type':'text/plain; charset=utf-8'});res.end('Não encontrado');
});
server.listen(PORT,()=>{console.log(`BH Story rodando em http://localhost:${PORT}`);if(!ADMIN_PASSWORD)console.warn('ATENÇÃO: defina ADMIN_EMAIL e ADMIN_PASSWORD no ambiente para habilitar o painel administrativo.');});
