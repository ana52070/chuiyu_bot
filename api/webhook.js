import crypto from 'crypto';
import { waitUntil } from '@vercel/functions';

const CORP_ID     = process.env.WXWORK_CORP_ID;
const AGENT_ID    = process.env.WXWORK_AGENT_ID;
const CORP_SECRET = process.env.WXWORK_SECRET;
const WX_TOKEN    = process.env.WXWORK_TOKEN;
const WX_AES_KEY  = Buffer.from((process.env.WXWORK_AES_KEY || '') + '=', 'base64');

const SUPABASE_URL    = process.env.SUPABASE_URL;
const SUPABASE_KEY    = process.env.SUPABASE_KEY;
const SILICONFLOW_KEY = process.env.SILICONFLOW_KEY;

function verifySignature(signature, timestamp, nonce, data = '') {
  const str = [WX_TOKEN, timestamp, nonce, data].sort().join('');
  return crypto.createHash('sha1').update(str).digest('hex') === signature;
}

function wxDecrypt(encrypted) {
  const buf = Buffer.from(encrypted, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-cbc', WX_AES_KEY, WX_AES_KEY.slice(0, 16));
  decipher.setAutoPadding(false);
  const dec = Buffer.concat([decipher.update(buf), decipher.final()]);
  const pad = dec[dec.length - 1];
  const content = dec.slice(16, dec.length - pad);
  const msgLen = content.readUInt32BE(0);
  return content.slice(4, 4 + msgLen).toString('utf-8');
}

function getXmlValue(xml, tag) {
  const m = xml.match(new RegExp(`<${tag}><!\\[CDATA\\[([\\s\\S]*?)\\]\\]><\\/${tag}>|<${tag}>([\\s\\S]*?)<\\/${tag}>`));
  return m ? (m[1] ?? m[2] ?? '') : '';
}

function getRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
    req.on('error', reject);
  });
}

async function getAccessToken() {
  const res = await fetch(`https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=${CORP_ID}&corpsecret=${CORP_SECRET}`);
  const data = await res.json();
  return data.access_token;
}

async function sendMessage(toUser, content) {
  const token = await getAccessToken();
  await fetch(`https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=${token}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ touser: toUser, msgtype: 'text', agentid: parseInt(AGENT_ID), text: { content } })
  });
}

async function getEmbedding(text) {
  const res = await fetch('https://api.siliconflow.cn/v1/embeddings', {
    method: 'POST',
    headers: { Authorization: `Bearer ${SILICONFLOW_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ model: 'BAAI/bge-m3', input: text.slice(0, 2000), encoding_format: 'float' })
  });
  const data = await res.json();
  return data.data[0].embedding;
}

async function searchDocuments(embedding) {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/rpc/match_documents`, {
    method: 'POST',
    headers: { apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ query_embedding: embedding, match_count: 5, match_threshold: 0.5 })
  });
  return res.json();
}

async function generateAnswer(question, contexts) {
  if (!contexts || contexts.length === 0)
    return '我在知识库中没有找到相关内容，请尝试换个问法。';
  const contextText = contexts.map(c => `【来源：${c.file_path}】\n${c.content}`).join('\n\n---\n\n');
  const prompt = `你是吹雨的个人知识库助手。\n\n知识库内容：\n${contextText}\n\n请根据以上内容回答问题，用中文简洁作答，注明来源。\n\n问题：${question}`;
  const res = await fetch('https://api.siliconflow.cn/v1/chat/completions', {
    method: 'POST',
    headers: { Authorization: `Bearer ${SILICONFLOW_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ model: 'deepseek-ai/DeepSeek-V3', messages: [{ role: 'user', content: prompt }], max_tokens: 1024, temperature: 0.3 })
  });
  const data = await res.json();
  return data.choices[0].message.content;
}

async function rag(question) {
  const embedding = await getEmbedding(question);
  const contexts  = await searchDocuments(embedding);
  return generateAnswer(question, contexts);
}

export default async function handler(req, res) {
  const urlObj = new URL(req.url, `https://${req.headers.host}`);
  const p = urlObj.searchParams;

  if (req.method === 'GET') {
    const sig = p.get('msg_signature') || '';
    const ts  = p.get('timestamp') || '';
    const nc  = p.get('nonce') || '';
    const es  = p.get('echostr') || '';
    if (verifySignature(sig, ts, nc, es)) {
      res.status(200).send(wxDecrypt(es));
    } else {
      res.status(403).send('Forbidden');
    }
    return;
  }

  if (req.method === 'POST') {
    const sig = p.get('msg_signature') || '';
    const ts  = p.get('timestamp') || '';
    const nc  = p.get('nonce') || '';

    const body = await getRawBody(req);
    const encrypted = getXmlValue(body, 'Encrypt');
    if (!encrypted) { res.status(400).send('Bad Request'); return; }
    if (!verifySignature(sig, ts, nc, encrypted)) { res.status(403).send('Forbidden'); return; }

    const xmlStr  = wxDecrypt(encrypted);
    const msgType = getXmlValue(xmlStr, 'MsgType');
    const userId  = getXmlValue(xmlStr, 'FromUserName');
    const content = getXmlValue(xmlStr, 'Content').trim();

    if (msgType === 'text' && userId && content) {
      // waitUntil 保证响应返回后函数继续运行
      waitUntil(
        rag(content)
          .then(answer => sendMessage(userId, answer))
          .catch(err => sendMessage(userId, `处理出错：${err.message}`))
      );
    }

    res.status(200).send('success');
    return;
  }

  res.status(405).send('Method Not Allowed');
}