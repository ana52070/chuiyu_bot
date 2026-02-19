import axios from 'axios';
import crypto from 'crypto';
import { parseStringPromise } from 'xml2js';

const CORP_ID     = process.env.WXWORK_CORP_ID;
const AGENT_ID    = process.env.WXWORK_AGENT_ID;
const CORP_SECRET = process.env.WXWORK_SECRET;
const WX_TOKEN    = process.env.WXWORK_TOKEN;
const WX_AES_KEY  = Buffer.from(process.env.WXWORK_AES_KEY + '=', 'base64');

const SUPABASE_URL    = process.env.SUPABASE_URL;
const SUPABASE_KEY    = process.env.SUPABASE_KEY;
const SILICONFLOW_KEY = process.env.SILICONFLOW_KEY;

// ── 企业微信签名验证 ──────────────────────────────────
function verifySignature(signature, timestamp, nonce, data = '') {
  const items = [WX_TOKEN, timestamp, nonce, data].sort().join('');
  const hash = crypto.createHash('sha1').update(items).digest('hex');
  return hash === signature;
}

// ── AES 解密 ─────────────────────────────────────────
function decrypt(encrypted) {
  const buf = Buffer.from(encrypted, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-cbc', WX_AES_KEY, WX_AES_KEY.slice(0, 16));
  decipher.setAutoPadding(false);
  const decrypted = Buffer.concat([decipher.update(buf), decipher.final()]);
  // 去掉 PKCS7 padding
  const pad = decrypted[decrypted.length - 1];
  const content = decrypted.slice(16, decrypted.length - pad);
  const msgLen = content.readUInt32BE(0);
  return content.slice(4, 4 + msgLen).toString('utf-8');
}

// ── AES 加密 ─────────────────────────────────────────
function encrypt(msg) {
  const random = crypto.randomBytes(16);
  const msgBuf = Buffer.from(msg, 'utf-8');
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(msgBuf.length);
  const corpBuf = Buffer.from(CORP_ID, 'utf-8');
  let plain = Buffer.concat([random, lenBuf, msgBuf, corpBuf]);
  // PKCS7 padding
  const pad = 32 - (plain.length % 32);
  const padBuf = Buffer.alloc(pad, pad);
  plain = Buffer.concat([plain, padBuf]);
  const cipher = crypto.createCipheriv('aes-256-cbc', WX_AES_KEY, WX_AES_KEY.slice(0, 16));
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(plain), cipher.final()]).toString('base64');
}

// ── 获取 access_token ────────────────────────────────
async function getAccessToken() {
  const res = await axios.get(
    `https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=${CORP_ID}&corpsecret=${CORP_SECRET}`
  );
  return res.data.access_token;
}

// ── 主动推送消息 ──────────────────────────────────────
async function sendMessage(toUser, content) {
  const token = await getAccessToken();
  await axios.post(
    `https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=${token}`,
    { touser: toUser, msgtype: 'text', agentid: parseInt(AGENT_ID), text: { content } }
  );
}

// ── Embedding ─────────────────────────────────────────
async function getEmbedding(text) {
  const res = await axios.post(
    'https://api.siliconflow.cn/v1/embeddings',
    { model: 'BAAI/bge-m3', input: text.slice(0, 2000), encoding_format: 'float' },
    { headers: { Authorization: `Bearer ${SILICONFLOW_KEY}` } }
  );
  return res.data.data[0].embedding;
}

// ── 向量检索 ──────────────────────────────────────────
async function searchDocuments(embedding) {
  const res = await axios.post(
    `${SUPABASE_URL}/rest/v1/rpc/match_documents`,
    { query_embedding: embedding, match_count: 5, match_threshold: 0.5 },
    { headers: { apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}` } }
  );
  return res.data;
}

// ── LLM 生成 ──────────────────────────────────────────
async function generateAnswer(question, contexts) {
  if (!contexts || contexts.length === 0) {
    return '我在知识库中没有找到相关内容，请尝试换个问法。';
  }
  const contextText = contexts
    .map(c => `【来源：${c.file_path}】\n${c.content}`)
    .join('\n\n---\n\n');

  const prompt = `你是吹雨的个人知识库助手，帮助主人检索和整理他的知识笔记。

下面是从知识库中检索到的相关内容：

${contextText}

---

请根据以上知识库内容，回答主人的问题。要求：
1. 回答要简洁、准确，直接基于知识库内容
2. 如果知识库内容不足以完整回答，请说明哪些部分有记录、哪些没有
3. 适当指出内容来源
4. 用中文回答

主人的问题：${question}`;

  const res = await axios.post(
    'https://api.siliconflow.cn/v1/chat/completions',
    {
      model: 'deepseek-ai/DeepSeek-V3',
      messages: [{ role: 'user', content: prompt }],
      max_tokens: 1024,
      temperature: 0.3,
    },
    { headers: { Authorization: `Bearer ${SILICONFLOW_KEY}` } }
  );
  return res.data.choices[0].message.content;
}

// ── RAG 主流程 ────────────────────────────────────────
async function rag(question) {
  const embedding = await getEmbedding(question);
  const contexts  = await searchDocuments(embedding);
  return generateAnswer(question, contexts);
}

// ── Vercel Edge Handler ───────────────────────────────
export const config = { runtime: 'edge' };

export default async function handler(req) {
  const url    = new URL(req.url);
  const params = url.searchParams;

  // GET：企业微信验证
  if (req.method === 'GET') {
    const msgSignature = params.get('msg_signature') || '';
    const timestamp    = params.get('timestamp') || '';
    const nonce        = params.get('nonce') || '';
    const echostr      = params.get('echostr') || '';

    if (verifySignature(msgSignature, timestamp, nonce, echostr)) {
      const decrypted = decrypt(echostr);
      return new Response(decrypted, { status: 200 });
    }
    return new Response('Forbidden', { status: 403 });
  }

  // POST：接收消息
  if (req.method === 'POST') {
    const msgSignature = params.get('msg_signature') || '';
    const timestamp    = params.get('timestamp') || '';
    const nonce        = params.get('nonce') || '';

    const body = await req.text();
    let encrypted;
    try {
      const parsed = await parseStringPromise(body);
      encrypted = parsed.xml.Encrypt[0];
    } catch {
      return new Response('Bad Request', { status: 400 });
    }

    if (!verifySignature(msgSignature, timestamp, nonce, encrypted)) {
      return new Response('Forbidden', { status: 403 });
    }

    const xmlStr  = decrypt(encrypted);
    const parsed  = await parseStringPromise(xmlStr);
    const msgType = parsed.xml.MsgType?.[0];
    const userId  = parsed.xml.FromUserName?.[0];
    const content = parsed.xml.Content?.[0]?.trim();

    if (msgType === 'text' && userId && content) {
      // waitUntil 让后台任务在响应返回后继续执行
      const ctx = req.waitUntil
        ? req
        : { waitUntil: (p) => p };

      ctx.waitUntil(
        rag(content)
          .then(answer => sendMessage(userId, answer))
          .catch(err => sendMessage(userId, `处理出错：${err.message}`))
      );
    }

    return new Response('success', { status: 200 });
  }

  return new Response('Method Not Allowed', { status: 405 });
}