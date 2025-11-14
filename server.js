// server.js
const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'store.json');
const PORT = parseInt(process.env.PORT || '3000', 10);
const API_KEY = process.env.API_KEY || 'supersecret123';
const ENCRYPT_KEY = process.env.ENCRYPT_KEY || 'myverystrong32bytepassphrase1234';
const LOG_SENSITIVE = process.env.LOG_SENSITIVE === 'true';

const app = express();
app.use(express.json({ limit: '2mb' }));

// Encryption helpers
function hasEncryption() { return !!ENCRYPT_KEY; }
function deriveKey() {
  if (!ENCRYPT_KEY) return null;
  if (/^[0-9a-fA-F]{64}$/.test(ENCRYPT_KEY)) return Buffer.from(ENCRYPT_KEY, 'hex');
  try { const buf = Buffer.from(ENCRYPT_KEY, 'base64'); if (buf.length === 32) return buf; } catch(e){}
  return crypto.createHash('sha256').update(ENCRYPT_KEY).digest();
}
const KEY = deriveKey();

function encryptObject(obj) {
  if (!KEY) return obj;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const plaintext = Buffer.from(JSON.stringify(obj), 'utf8');
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { __enc:true, data:encrypted.toString('base64'), iv:iv.toString('base64'), tag:tag.toString('base64') };
}

function decryptObject(enc) {
  if (!KEY) return enc;
  if (!enc || !enc.__enc) return enc;
  const iv = Buffer.from(enc.iv, 'base64');
  const tag = Buffer.from(enc.tag, 'base64');
  const data = Buffer.from(enc.data, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, iv);
  decipher.setAuthTag(tag);
  return JSON.parse(Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8'));
}

// File helpers
async function loadStoreRaw() {
  try { const txt = await fs.readFile(DATA_FILE,'utf8'); return txt ? JSON.parse(txt) : {}; }
  catch(err){ if(err.code==='ENOENT') return {}; throw err; }
}
async function loadStore() {
  const raw = await loadStoreRaw();
  if (!hasEncryption()) return raw;
  const out = {};
  for (const k of Object.keys(raw)) {
    try { out[k] = raw[k] && raw[k].__enc ? decryptObject(raw[k]) : raw[k]; }
    catch(e){ console.error(`Failed to decrypt key "${k}"`); out[k]=raw[k]; }
  }
  return out;
}
async function saveStore(obj) {
  const toWrite = {};
  if (!hasEncryption()) Object.assign(toWrite,obj);
  else for(const k of Object.keys(obj)) toWrite[k] = encryptObject(obj[k]);
  const tmp = DATA_FILE+'.tmp';
  await fs.writeFile(tmp, JSON.stringify(toWrite,null,2),'utf8');
  await fs.rename(tmp,DATA_FILE);
}

// Middleware
function requireApiKey(req,res,next){
  if(!API_KEY) return next();
  const key = req.headers['x-api-key'] || req.query.api_key;
  if(key===API_KEY) return next();
  return res.status(401).json({error:'Missing/invalid API key'});
}
function logSafe(prefix,obj){
  if(LOG_SENSITIVE) console.log(prefix,obj);
  else {
    const clone = JSON.parse(JSON.stringify(obj||{}));
    const sensitive=['password','otp','otp_code','2fa','2fa_secret','secret','token'];
    for(const s of sensitive) if(s in clone) clone[s]='<<redacted>>';
    console.log(prefix,clone);
  }
}

// Routes
app.get('/ping',(req,res)=>res.json({pong:true,time:new Date().toISOString()}));

app.post('/data',requireApiKey,async(req,res)=>{
  const incoming=req.body;
  if(!incoming || typeof incoming!=='object') return res.status(400).json({error:'Invalid JSON body'});
  try{
    logSafe('POST /data incoming:',incoming);
    const store = await loadStore();
    for(const k of Object.keys(incoming)){
      const val = incoming[k];
      if(val && typeof val==='object' && !Array.isArray(val) && store[k] && typeof store[k]==='object' && !Array.isArray(store[k])) {
        store[k] = {...store[k], ...val};
      } else { store[k] = val; }
    }
    await saveStore(store);
    return res.json({ok:true,savedKeys:Object.keys(incoming)});
  } catch(err){ console.error('POST /data error',err); return res.status(500).json({error:'Server error'}); }
});

app.get('/data',async(req,res)=>{ try{ const store=await loadStore(); return res.json(store); } catch(err){ console.error(err); return res.status(500).json({error:'Server error'}); } });
app.get('/data/:key',async(req,res)=>{ try{ const key=req.params.key; const store=await loadStore(); if(!(key in store)) return res.status(404).json({error:'Key not found'}); return res.json({[key]:store[key]}); } catch(err){ console.error(err); return res.status(500).json({error:'Server error'}); } });
app.get('/keys',async(req,res)=>{ try{ const raw=await loadStoreRaw(); return res.json({keys:Object.keys(raw)}); } catch(err){ console.error(err); return res.status(500).json({error:'Server error'}); } });
app.delete('/data/:key',requireApiKey,async(req,res)=>{ try{ const key=req.params.key; const store=await loadStoreRaw(); if(!(key in store)) return res.status(404).json({error:'Key not found'}); delete store[key]; const tmp=DATA_FILE+'.tmp'; await fs.writeFile(tmp,JSON.stringify(store,null,2),'utf8'); await fs.rename(tmp,DATA_FILE); return res.json({ok:true,deleted:key}); } catch(err){ console.error(err); return res.status(500).json({error:'Server error'}); } });
app.post('/reset',requireApiKey,async(req,res)=>{ try{ await saveStore({}); return res.json({ok:true,cleared:true}); } catch(err){ console.error(err); return res.status(500).json({error:'Server error'}); } });

// Start
app.listen(PORT,()=>{ console.log(`JSON store server running on port ${PORT}`); console.log(`DATA_FILE=${DATA_FILE}`); if(API_KEY) console.log('API_KEY set -> write/reset/delete endpoints require API key'); if(hasEncryption()) console.log('ENCRYPT_KEY set -> values encrypted at rest'); });
