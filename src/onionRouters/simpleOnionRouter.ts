import bodyParser from "body-parser";
import express from "express";
//Add of the REGISTRY_PORT importation
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
//New imports from registry and crypto
import {Node} from "../registry/registry";
import {exportPrvKey, exportPubKey, generateRsaKeyPair, rsaDecrypt, symDecrypt} from "../crypto";


export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());


  //Declaration of the variables
  let rsaKeyPair = await generateRsaKeyPair();
  let pubKey = await exportPubKey(rsaKeyPair.publicKey);
  let privateKey = rsaKeyPair.privateKey;

  let node: Node = { nodeId: nodeId, pubKey: pubKey };

  let lastReceivedEncryptedMessage: string | null = null;
  let lastReceivedDecryptedMessage: string | null = null;
  let lastMessageDestination: number | null = null;

  // TODO implement the status route
  // onionRouter.get("/status", (req, res) => {});
  onionRouter.get("/status/", (req, res) => {
    res.send("live");
  });

  //getLastReceivedEncryptedMessage
  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
    res.status(200).json({result: lastReceivedEncryptedMessage});
  });

  //getLastReceivedDecryptedMessage
  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
    res.status(200).json({result: lastReceivedDecryptedMessage});
  });

  //getLastMessageDestination
  onionRouter.get("/getLastMessageDestination", (req, res) => {
    res.status(200).json({result: lastMessageDestination});
  });

  //getPrivateKey
  onionRouter.get("/getPrivateKey", async (req, res) => {
    res.status(200).json({result: await exportPrvKey(privateKey)});
  });

  //POST message
  onionRouter.post("/message", async (req, res) => {
    const {message} = req.body;
    const decrypted = await rsaDecrypt(message.slice(0, 344), privateKey);
    const decryptedMessage = await symDecrypt(decrypted, message.slice(344));
    const nextDestination = parseInt(decryptedMessage.slice(0, 10), 10);
    const remainingMessage = decryptedMessage.slice(10);

    lastReceivedEncryptedMessage = message;
    lastReceivedDecryptedMessage = remainingMessage;
    lastMessageDestination = nextDestination;

    await fetch(`http://localhost:${nextDestination}/message`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ message: remainingMessage }),
    });
    res.status(200).send("ok");
  });

  await fetch(`http://localhost:${REGISTRY_PORT}/registerNode`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      nodeId: nodeId,
      pubKey: pubKey,
    })
  });

  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(
      `Onion router ${nodeId} is listening on port ${
        BASE_ONION_ROUTER_PORT + nodeId
      }`
    );
  });

  return server;
}
