import axios from "axios";

const client = axios.create({
  baseURL: "http://127.0.0.1:8000",
  timeout: 8000,
});

export async function fetchChildren(nodeName) {
  const res = await client.get("/children", { params: { node: nodeName } });
  return res.data;
}

export async function fetchNode(nodeName) {
  const res = await client.get(`/node/${encodeURIComponent(nodeName)}`);
  return res.data;
}

export async function fetchDefenses(attackName) {
  const res = await client.get("/defenses", { params: { attack: attackName } });
  return res.data;
}

export async function fetchTools(attackName) {
  const res = await client.get("/tools", { params: { attack: attackName } });
  return res.data;
}

export async function fetchRelated(nodeName) {
  const res = await client.get("/related", { params: { node: nodeName } });
  return res.data;
}

export async function fetchPath(start, end) {
  const res = await client.get("/path", { params: { start, end } });
  return res.data;
}

export async function fetchQuestions() {
  const res = await client.get("/questions");
  return res.data;
}

export async function askQuestion(questionId, detailLevel = "concise") {
  const res = await client.post("/question", {
    question_id: questionId,
    detail_level: detailLevel,
  });
  return res.data;
}

/**
 * Case-insensitive substring search across node names, used by
 * Free-Flow Mode's search bar.
 */
export async function searchNodes(q) {
  const res = await client.get("/search", { params: { q } });
  return res.data;
}

export default client;