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

// 获取一次 token，复用于多次发消息
async function getAccessToken() {
  const res = await fetch(`https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=${CORP_ID}&corpsecret=${CORP_SECRET}`);
  const data = await res.json();
  console.log('[TOKEN] errcode:', data.errcode, 'token_prefix:', data.access_token?.slice(0, 10));
  return data.access_token;
}

async function sendMessageWithToken(token, toUser, content) {
  console.log('[SEND] 发送消息，长度:', content.length);
  const WORKER_URL = "http://49.233.85.74:8080";
  const res = await fetch(WORKER_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      access_token: token,
      payload: { touser: toUser, msgtype: 'text', agentid: parseInt(AGENT_ID), text: { content } }
    })
  });
  const result = await res.json();
  console.log('[SEND] 企业微信返回:', JSON.stringify(result));
  return result;
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

    console.log('[MSG] userId:', userId, 'content:', content);

    if (msgType === 'text' && userId && content) {
      waitUntil(
        (async () => {
          // 只获取一次 token，两条消息复用
          const token = await getAccessToken();

          // 第一条：立即确认
          await sendMessageWithToken(token, userId, '等我好好想想哈,别着急马上好');

          // RAG
          let answer;
          try {
            console.log('[RAG] 开始');
            const embedding = await getEmbedding(content);
            console.log('[RAG] embedding完成');
            const contexts = await searchDocuments(embedding);
            console.log('[RAG] 检索完成，文档数:', contexts?.length);
            answer = await generateAnswer(content, contexts);
            console.log('[RAG] 生成完成，长度:', answer?.length);
          } catch (err) {
            console.error('[RAG ERROR]', err.message);
            answer = `处理出错：${err.message}`;
          }

          // 第二条：发 RAG 结果，复用同一个 token
          await sendMessageWithToken(token, userId, answer);
        })()
      );
    }

    res.status(200).send('success');
    return;
  }

  res.status(405).send('Method Not Allowed');
}