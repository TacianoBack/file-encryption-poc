import * as fs from "fs";
import * as crypto from "crypto";
import * as dotenv from "dotenv";

dotenv.config();

// Função para gerar um salt aleatório
export function generateSalt(length: number = 16): Buffer {
  return crypto.randomBytes(length);
}

const SALT_LENGTH = 16;
const IV_LENGTH = 16;
const ALGORITHM = "aes-256-gcm";
const AUTH_TAG_LENGTH = 16;
const DEFAULT_PASSWORD = process.env.PASSWORD || "senha-forte";

function readSaltIvAuthTag(filePath: string) {
  const fd = fs.openSync(filePath, "r");
  const stats = fs.statSync(filePath);
  const salt = Buffer.alloc(SALT_LENGTH);
  const iv = Buffer.alloc(IV_LENGTH);
  const authTag = Buffer.alloc(AUTH_TAG_LENGTH);
  fs.readSync(fd, salt, 0, SALT_LENGTH, 0);
  fs.readSync(fd, iv, 0, IV_LENGTH, SALT_LENGTH);
  fs.readSync(fd, authTag, 0, AUTH_TAG_LENGTH, stats.size - AUTH_TAG_LENGTH);
  fs.closeSync(fd);
  return { salt, iv, authTag, stats };
}

function createKey(password: string, salt: Buffer) {
  return crypto.scryptSync(password, salt, 32);
}

function createCipher(key: Buffer, iv: Buffer) {
  return crypto.createCipheriv(ALGORITHM, key, iv);
}

function createDecipher(key: Buffer, iv: Buffer, authTag: Buffer) {
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);
  return decipher;
}

// Função para criptografar um arquivo usando streams
export function encryptFile({
  inputPath,
  outputPath,
  password,
}: {
  inputPath: string;
  outputPath: string;
  password: string;
}): Promise<void> {
  return new Promise((resolve, reject) => {
    const salt = generateSalt(SALT_LENGTH);
    const iv = crypto.randomBytes(IV_LENGTH);
    const key = createKey(password, salt);
    const input = fs.createReadStream(inputPath);
    const output = fs.createWriteStream(outputPath);
    const cipher = createCipher(key, iv);
    // Escreve salt + IV no início do arquivo
    output.write(Buffer.concat([salt, iv]), (err) => {
      if (err) return reject(err);
      input.pipe(cipher).pipe(output, { end: false });
      cipher.on("end", () => {
        // Escreve o authentication tag ao final do arquivo
        output.write(cipher.getAuthTag(), (err2) => {
          if (err2) return reject(err2);
          output.end();
        });
      });
      output.on("finish", resolve);
      output.on("error", reject);
      input.on("error", reject);
    });
  });
}

// Função para descriptografar um arquivo usando streams
export function decryptFile({
  inputPath,
  outputPath,
  password,
}: {
  inputPath: string;
  outputPath: string;
  password: string;
}): Promise<void> {
  return new Promise((resolve, reject) => {
    const { salt, iv, authTag, stats } = readSaltIvAuthTag(inputPath);
    const key = createKey(password, salt);
    const input = fs.createReadStream(inputPath, {
      start: SALT_LENGTH + IV_LENGTH,
      end: stats.size - AUTH_TAG_LENGTH - 1,
    });
    const output = fs.createWriteStream(outputPath);
    const decipher = createDecipher(key, iv, authTag);
    input.pipe(decipher).pipe(output);
    output.on("finish", resolve);
    output.on("error", reject);
    input.on("error", reject);
  });
}

function runEncrypt() {
  const inputPath = process.env.INPUT_FILE || "./test-file.zip";
  const outputPath = process.env.OUTPUT_FILE || "./test-file.zip.enc";

  return encryptFile({
    inputPath,
    outputPath,
    password: DEFAULT_PASSWORD,
  }).then(() => {
    console.log("Arquivo criptografado com sucesso:", outputPath);
  });
}

function runDecrypt() {
  const outputPath = process.env.OUTPUT_FILE || "./test-file.zip.enc";
  const decryptedOutputPath =
    process.env.DECRYPTED_FILE || "./test-file-decrypted.zip";
  return decryptFile({
    inputPath: outputPath,
    outputPath: decryptedOutputPath,
    password: DEFAULT_PASSWORD,
  }).then(() => {
    console.log("Arquivo descriptografado com sucesso:", decryptedOutputPath);
  });
}

if (String(process.env?.TEST) !== "true") {
  runEncrypt()
    .then(() => runDecrypt())
    .catch((err) => {
      console.error("Erro ao criptografar/descriptografar o arquivo:", err);
    });
}
