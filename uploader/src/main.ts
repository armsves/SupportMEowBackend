import { verifyADR36Amino } from '@keplr-wallet/cosmos'
import errorHandler from 'api-error-handler'
import bodyParser from 'body-parser'
import cors from 'cors'
import cuid from 'cuid'
import express from 'express'
import asyncHandler from 'express-async-handler'
import { AsteroidClient } from './asteroid-client.js'
import { loadConfig } from './config.js'
import { connect } from './db.js'
import { createS3Client, generateUploadURL } from './s3.js'

import {
  InscriptionOperations,
  SigningStargateClient,
} from '@asteroid-protocol/sdk'
import { AccountData, DirectSecp256k1HdWallet } from '@cosmjs/proto-signing'
import { GasPrice } from '@cosmjs/stargate'
import { sha256 } from '@cosmjs/crypto'
import { toHex } from '@cosmjs/encoding'

import { request } from "graphql-request";

///////////

import pkg from 'clarifai-nodejs';
const { Model, Input } = pkg;

async function classifyAnimalByBytes(imageBytes: Uint8Array): Promise<string> {
  const modelUrl = "https://clarifai.com/clarifai/main/models/general-image-recognition";

  const model = new Model({
    url: modelUrl,
    authConfig: { pat: "fb7087ca347d49ed8ae63b355839ec9f" },
  });

  try {
    const modelPrediction = await model.predictByBytes({
      inputBytes: Buffer.from(imageBytes),
      inputType: "image"
    });

    if (modelPrediction?.[0]?.data) {
      const animal = modelPrediction[0].data.conceptsList.length > 0
        ? modelPrediction[0].data.conceptsList[0].name
        : 'No concepts available';
      //console.log('First concept name:', animal);
      return animal === 'cat' ? 'cat' : 'not a cat';
    } else {
      console.log('No data available');
      return 'No concepts available';
    }
  } catch (error) {
    console.error('Error classifying animal:', error);
    return 'Error';
  }
}

////////////

export function hashContent(content: Uint8Array): string {
  return toHex(sha256(content))
}

const network = {
  gasPrice: '0.005uatom',
  chainId: 'theta-testnet-001',
  // rpc: 'https://rpc.sentry-01.theta-testnet.polypore.xyz',
  rpc: 'https://rpc-t.cosmos.nodestake.org',
  explorer: 'https://www.mintscan.io/cosmos-testnet/tx/',
  api: 'https://testnet-new-api.asteroidprotocol.io/v1/graphql',
}

async function getSigner(): Promise<[DirectSecp256k1HdWallet, AccountData]> {
  const wallet = await DirectSecp256k1HdWallet.fromMnemonic(config.MNEMONIC)
  const accounts = await wallet.getAccounts()
  return [wallet, accounts[0]]
}

//////////

const app = express()
//app.use(bodyParser.json())
app.use(bodyParser.json({ limit: '1mb' })); // Increase body size limit to 50MB

app.use(cors())
const config = loadConfig()
const s3Client = createS3Client(config)
const db = connect(config.DATABASE_URL)


function base64ToUint8Array(base64: string): Uint8Array {
  const binaryString = Buffer.from(base64, 'base64').toString('binary');
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

app.get('/', (req, res) => {
  res.send('Hello, this is the backend server!')
})

async function inscribe(name: string, description: string, creator: string, price: string, image: string) {
  console.log('Inscribe this:', name, description, creator, price)

  const [signer, account] = await getSigner()
  const operations = new InscriptionOperations(network.chainId, account.address)
  const base64Data = image.replace(/^data:image\/\w+;base64,/, '');
  const hashData = hashContent(base64ToUint8Array(base64Data));
  console.log('hashData:', hashData);
  const data = base64ToUint8Array(base64Data);
  console.log('data:', data);
  const animalType = await classifyAnimalByBytes(data);
  //if animalType === 'Error') {
  console.log('animalType:', animalType);

  const txData = operations.inscribe(data, {
    mime: 'image/png',
    name: name,
    description: description,
    price: price,
  }, { type: '/cosmos.bank.Account', identifier: creator })

  //console.log('txData:', txData);

  // connect client
  const client = await SigningStargateClient.connectWithSigner(
    network.rpc,
    signer,
    { gasPrice: GasPrice.fromString(network.gasPrice) },
  )
  //console.log('client:', client);

  // broadcast tx
  const res = await client.signAndBroadcast(
    account.address,
    txData.messages,
    'auto',
    txData.memo,
    undefined,
    txData.nonCriticalExtensionOptions,
  )
  //console.log('res', res)
  console.log(`${network.explorer}${res.transactionHash}`)

  return res
}


async function fetchInscriptionData(transactionHash: string) {
  const endpoint = 'https://testnet-new-api.asteroidprotocol.io/v1/graphql';
  const query = `
    query {
      inscription(where: { transaction: { hash: { _eq: "${transactionHash}" } } }) {
        metadata
        content_path
        content_hash
      }
    }
  `;

  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ query }),
  });

  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }

  const data = await response.json();
  return data;
}

async function fetchInscriptionDataWithRetry(transactionHash: string) {
  const maxRetries = 30;
  const retryDelay = 1000; // 1 second

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    const inscriptionData: any = await fetchInscriptionData(transactionHash);

    if (inscriptionData.data.inscription.length > 0) {
      return inscriptionData;
    }

    if (attempt < maxRetries) {
      console.log(`Attempt ${attempt} failed. Retrying in ${retryDelay / 1000} seconds...`);
      await new Promise(resolve => setTimeout(resolve, retryDelay));
    } else {
      throw new Error('Max retries reached. Inscription data is still empty.');
    }
  }
}


app.post(
  '/execute',
  asyncHandler(async (req, res) => {
    const { name, description, creator, price, image } = req.body;

    try {
      const response = await inscribe(name, description, creator, price, image);
      const inscriptionData = await fetchInscriptionDataWithRetry(response.transactionHash);
      res.json({ transactionHash: response.transactionHash, inscriptionData });
    } catch (error) {
      console.error('Error executing inscribe function:', error);
      res.status(500).send('Error executing inscribe function');
    }

  }),
);

interface InscriptionMetadata {
  metadata: {
    parent: {
      type: string;
      identifier: string;
    };
    metadata: {
      mime: string;
      name: string;
      description: string;
      price: string;
      creator: string;
    };
  };
  content_path: string;
  content_hash: string;
}

interface QueryResponse {
  inscription: InscriptionMetadata[];
}

app.post(
  '/verify',
  asyncHandler(async (req, res) => {
    const { image, txHash } = req.body;

    try {
      console.log('txHash:', txHash);
      const base64Data = image.replace(/^data:image\/\w+;base64,/, '');
      const hashData = hashContent(base64ToUint8Array(base64Data));
      console.log('hashData:', hashData);

      const QUERY = `
          query {
                  inscription(where: { transaction: { hash: { _eq: "${txHash}" } } }) {
                    metadata
                    content_path
                    content_hash
                  }
          }
      `;
      const response = await request<QueryResponse>(
        "https://testnet-new-api.asteroidprotocol.io/v1/graphql",
        QUERY,
      );
      const contentHash = response.inscription.length > 0 ? response.inscription[0].content_hash : 'No content hash available';

      console.log('response:', contentHash);

      if (hashData.toString() === contentHash.toString()) {
        console.log('Transaction hash matches content hash');
        res.json({ response: 'Transaction hash matches content hash' });
      } else {
        console.log('Content hash doesnt match');
        res.status(500).send('Content hash doesnt match');
      }

      //res.json({ response: contentHash });
    } catch (error) {
      console.error('Error executing verify function:', error);
      res.status(500).send('Error executing verify function');
    }

  }),
);

const server = app.listen(process.env.PORT, () => {
  console.log(`Server listening on port ${process.env.PORT}`)
})

process.on('SIGINT', async function () {
  console.log('SIGINT signal received: closing HTTP server')
  server.close(() => {
    process.exit()
  })
})

process.on('SIGTERM', async function () {
  console.log('SIGTERM signal received: closing HTTP server')
  server.close(() => {
    process.exit()
  })
})

interface InscriptionUrls {
  inscriptionSignedUrl: string
  metadataSignedUrl: string
}

interface InscriptionUrlsResponse extends InscriptionUrls {
  tokenId: number
}

function getMetadataUrl(folder: string, tokenId: number) {
  return generateUploadURL(
    s3Client,
    config.S3_BUCKET,
    folder,
    `${tokenId}_metadata.json`,
    'application/json',
  )
}

async function getInscriptionSignedUrls(
  launchHash: string,
  folder: string,
  tokenId: number,
  name: string,
  contentType: string,
): Promise<InscriptionUrls> {
  // create launchpad inscription record
  await db('launchpad_inscription')
    .insert({
      launchpad_hash: launchHash,
      inscription_number: tokenId,
      name,
    })
    .onConflict(['launchpad_hash', 'inscription_number'])
    .ignore()

  // generate signed URLs
  const inscriptionSignedUrl = await generateUploadURL(
    s3Client,
    config.S3_BUCKET,
    folder,
    name,
    contentType,
  )
  const metadataSignedUrl = await getMetadataUrl(folder, tokenId)

  return {
    inscriptionSignedUrl,
    metadataSignedUrl,
  }
}

interface Inscription {
  tokenId: number
  filename: string
  contentType: string
}

app.post(
  '/create-session',
  asyncHandler(async (req, res) => {
    const { address } = req.body

    // check if session already exists
    const existingSession = await db('session')
      .select()
      .where({ address })
      .first()

    if (existingSession) {
      res.json({ hash: existingSession.hash })
      return
    }

    // create new session
    const hash = cuid()

    await db('session').insert({
      address,
      hash,
      date_created: new Date(),
      verified: false,
    })

    res.json({ hash })
  }),
)

app.post(
  '/verify-session',
  asyncHandler(async (req, res) => {
    const { hash, pubkey, signature } = req.body

    const session = await db('session').select().where({ hash }).first()

    if (!session) {
      res.status(404).json({ status: 404, message: 'Session not found' })
      return
    }

    const verified = verifyADR36Amino(
      'cosmos',
      session.address,
      hash,
      Buffer.from(pubkey, 'base64'),
      Buffer.from(signature, 'base64'),
    )

    if (!verified) {
      res
        .status(403)
        .json({ status: 403, message: 'Signature verification failed' })
      return
    }

    await db('session').where({ hash }).update({ verified: true })

    res.json({ success: true })
  }),
)

app.get(
  '/launchpads',
  asyncHandler(async (req, res) => {
    const launchpads = await db('launchpad_inscription')
      .select('launchpad_hash')
      .count({ total: 'inscription_number' })
      .count({ uploaded: db.raw('CASE WHEN uploaded THEN 1 END') })
      .groupBy('launchpad_hash')

    res.json(
      launchpads.map((launchpad) => ({
        launchpad_hash: launchpad.launchpad_hash,
        total: parseInt(launchpad.total as string),
        uploaded: parseInt(launchpad.uploaded as string),
      })),
    )
  }),
)

app.get(
  '/launchpad/:launchHash',
  asyncHandler(async (req, res) => {
    const launchpad = await db('launchpad_inscription')
      .count({ total: 'inscription_number' })
      .count({ uploaded: db.raw('CASE WHEN uploaded THEN 1 END') })
      .where({ launchpad_hash: req.params.launchHash })
      .first()

    if (!launchpad) {
      res.status(404).json({ status: 404, message: 'Launchpad not found' })
      return
    }

    res.json({
      total: parseInt(launchpad.total as string),
      uploaded: parseInt(launchpad.uploaded as string),
    })
  }),
)

app.get(
  '/public/inscriptions/:launchHash',
  asyncHandler(async (req, res) => {
    const { launchHash } = req.params
    const asteroidClient = new AsteroidClient(config.ASTEROID_API)
    const maxSupply = await asteroidClient.getCollectionSupply(launchHash)
    if (maxSupply === null) {
      res.status(404).json({ status: 404, message: 'Launchpad not found' })
      return
    }

    if (maxSupply !== 0) {
      res.status(403).json({ status: 403, message: 'Launchpad is not public' })
    }

    const launchpad = await db('launchpad')
      .select('folder')
      .where({ hash: launchHash })
      .first()
    if (!launchpad) {
      res.status(404).json({ status: 404, message: 'Launchpad not found' })
      return
    }

    const inscriptions = await db('launchpad_inscription')
      .select()
      .where({ launchpad_hash: launchHash, uploaded: true })

    res.json({ inscriptions, folder: launchpad.folder })
  }),
)

app.post(
  '/inscriptions/:launchHash',
  asyncHandler(async (req, res) => {
    const { launchHash } = req.params
    const { sessionHash } = req.body as {
      sessionHash: string
    }

    // check session
    const session = await db('session')
      .select()
      .where({ hash: sessionHash ?? null, verified: true })
      .first()
    if (!session || !session.verified) {
      res.status(403).json({ status: 403, message: 'Invalid session' })
      return
    }

    // get launchpad exists and user is owner
    const launchpad = await db('launchpad')
      .select('folder')
      .where({ hash: launchHash, creator: session.address })
      .first()

    if (!launchpad) {
      res.status(404).json({ status: 404, message: 'Launchpad not found' })
      return
    }

    const inscriptions = await db('launchpad_inscription')
      .select()
      .where({ launchpad_hash: launchHash, uploaded: true })

    res.json({ inscriptions, folder: launchpad.folder })
  }),
)

app.post(
  '/inscription/bulk/upload',
  asyncHandler(async (req, res) => {
    const { launchHash, inscriptions, sessionHash } = req.body as {
      launchHash: string
      inscriptions: Inscription[]
      sessionHash: string
    }

    // check session
    const session = await db('session')
      .select()
      .where({ hash: sessionHash ?? null, verified: true })
      .first()
    if (!session || !session.verified) {
      res.status(403).json({ status: 403, message: 'Invalid session' })
      return
    }

    // check if launchpad exists
    const launchpad = await db('launchpad')
      .select()
      .where({ hash: launchHash, creator: session.address })
      .first()
    let folder: string

    if (!launchpad) {
      // @todo check if launchpad is owned by session address
      folder = cuid()
      await db('launchpad').insert({
        hash: launchHash,
        creator: session.address,
        folder,
      })
    } else {
      folder = launchpad.folder
    }

    const urls: InscriptionUrlsResponse[] = []
    for (const inscription of inscriptions) {
      const { inscriptionSignedUrl, metadataSignedUrl } =
        await getInscriptionSignedUrls(
          launchHash,
          folder,
          inscription.tokenId,
          inscription.filename,
          inscription.contentType,
        )
      urls.push({
        inscriptionSignedUrl,
        metadataSignedUrl,
        tokenId: inscription.tokenId,
      })
    }

    res.json({ urls })
  }),
)

app.post(
  '/inscription/bulk/confirm',
  asyncHandler(async (req, res) => {
    const { launchHash, tokenIds, sessionHash } = req.body as {
      launchHash: string
      tokenIds: number[]
      sessionHash: string
    }

    // check session
    const session = await db('session')
      .select()
      .where({ hash: sessionHash ?? null, verified: true })
      .first()
    if (!session || !session.verified) {
      res.status(403).json({ status: 403, message: 'Invalid session' })
      return
    }

    // check if launchpad exists
    const launchpad = await db('launchpad')
      .select()
      .where({ hash: launchHash, creator: session.address })
      .first()
    if (!launchpad) {
      res.status(404).json({ status: 404, message: 'Launchpad not found' })
      return
    }

    // update inscription records
    await db('launchpad_inscription')
      .whereIn('inscription_number', tokenIds)
      .andWhere({ launchpad_hash: launchHash })
      .update({ uploaded: true })

    res.json({ success: true })
  }),
)

async function getNextTokenId(launchHash: string) {
  const maxTokenIdRes = await db('launchpad_inscription')
    .max('inscription_number')
    .where({ launchpad_hash: launchHash })
    .first()

  return (maxTokenIdRes?.['max'] ?? 0) + 1
}

async function getNextAssetId(launchHash: string) {
  const maxTokenIdRes = await db('launchpad_asset')
    .max('asset_id')
    .where({ launchpad_hash: launchHash })
    .first()

  return (maxTokenIdRes?.['max'] ?? 0) + 1
}

app.post(
  '/asset/upload',
  asyncHandler(async (req, res) => {
    const { launchHash, contentType, extension } = req.body

    // check if launchpad exists, @todo check if launchpad allows reservations to upload files
    const launchpad = await db('launchpad')
      .select()
      .where({ hash: launchHash })
      .first()
    if (!launchpad) {
      res.status(404).json({ status: 404, message: 'Launchpad not found' })
      return
    }

    // get next asset id
    const nextAssetId = await getNextAssetId(launchHash)
    const name = `${nextAssetId}.${extension}`

    // create launchpad asset record
    await db('launchpad_asset').insert({
      launchpad_hash: launchHash,
      asset_id: nextAssetId,
      name,
    })

    // generate signed URLs
    const signedUrl = await generateUploadURL(
      s3Client,
      config.S3_BUCKET,
      launchpad.folder,
      name,
      contentType,
    )

    res.json({
      assetId: nextAssetId,
      signedUrl,
      filename: name,
      folder: launchpad.folder,
    })
  }),
)

app.post(
  '/asset/confirm',
  asyncHandler(async (req, res) => {
    const { launchHash, assetId } = req.body

    // check if launchpad exists, @todo check if launchpad allows reservations to upload files
    const launchpad = await db('launchpad')
      .select()
      .where({ hash: launchHash })
      .first()
    if (!launchpad) {
      res.status(404).json({ status: 404, message: 'Launchpad not found' })
      return
    }

    // update inscription asset
    await db('launchpad_asset')
      .where({
        launchpad_hash: launchHash,
        asset_id: assetId,
      })
      .update({ uploaded: true })

    res.json({ success: true })
  }),
)

app.post(
  '/inscription/upload',
  asyncHandler(async (req, res) => {
    const { launchHash, contentType, extension, sessionHash } = req.body

    // check session
    const session = await db('session')
      .select()
      .where({ hash: sessionHash ?? null, verified: true })
      .first()
    if (!session || !session.verified) {
      res.status(403).json({ status: 403, message: 'Invalid session' })
      return
    }

    // check if launchpad exists
    const launchpad = await db('launchpad')
      .select()
      .where({ hash: launchHash, creator: session.address })
      .first()
    let folder: string
    if (!launchpad) {
      // @todo check if launchpad is owned by session address
      folder = cuid()
      await db('launchpad').insert({
        hash: launchHash,
        creator: session.address,
        folder,
      })
    } else {
      folder = launchpad.folder
    }

    // get next token id
    const nextTokenId = await getNextTokenId(launchHash)
    const name = `${nextTokenId}.${extension}`

    const { inscriptionSignedUrl, metadataSignedUrl } =
      await getInscriptionSignedUrls(
        launchHash,
        folder,
        nextTokenId,
        name,
        contentType,
      )

    res.json({
      tokenId: nextTokenId,
      inscriptionSignedUrl,
      metadataSignedUrl,
    } as InscriptionUrlsResponse)
  }),
)

app.post(
  '/inscription/edit',
  asyncHandler(async (req, res) => {
    const { launchHash, tokenId, sessionHash } = req.body

    // check session
    const session = await db('session')
      .select()
      .where({ hash: sessionHash ?? null, verified: true })
      .first()
    if (!session || !session.verified) {
      res.status(403).json({ status: 403, message: 'Invalid session' })
      return
    }

    // check if launchpad exists
    const launchpad = await db('launchpad')
      .select()
      .where({ hash: launchHash, creator: session.address })
      .first()
    if (!launchpad) {
      res.status(404).json({ status: 404, message: 'Launchpad not found' })
      return
    }

    // get inscription record
    const inscription = await db('launchpad_inscription')
      .select()
      .where({
        launchpad_hash: launchHash,
        inscription_number: tokenId,
      })
      .first()

    if (!inscription) {
      res.status(404).json({ status: 404, message: 'Inscription not found' })
      return
    }

    const metadataSignedUrl = await getMetadataUrl(launchpad.folder, tokenId)

    res.json({ metadataSignedUrl })
  }),
)

app.post(
  '/inscription/confirm',
  asyncHandler(async (req, res) => {
    const { launchHash, tokenId, sessionHash } = req.body

    // check session
    const session = await db('session')
      .select()
      .where({ hash: sessionHash ?? null, verified: true })
      .first()
    if (!session || !session.verified) {
      res.status(403).json({ status: 403, message: 'Invalid session' })
      return
    }

    // check if launchpad exists
    const launchpad = await db('launchpad')
      .select()
      .where({ hash: launchHash, creator: session.address })
      .first()

    if (!launchpad) {
      res.status(404).json({ status: 404, message: 'Launchpad not found' })
      return
    }

    // get inscription record
    const inscription = await db('launchpad_inscription')
      .select()
      .where({
        launchpad_hash: launchHash,
        inscription_number: tokenId,
      })
      .first()

    if (!inscription) {
      res.status(404).json({ status: 404, message: 'Inscription not found' })
      return
    }

    // update inscription record
    await db('launchpad_inscription')
      .where({
        launchpad_hash: launchHash,
        inscription_number: tokenId,
      })
      .update({ uploaded: true })

    res.json({ success: true })
  }),
)

app.use(errorHandler())
