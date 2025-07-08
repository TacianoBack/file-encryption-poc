import * as fs from "fs";
import * as crypto from "crypto";
import * as dotenv from "dotenv";

dotenv.config();

const SALT = crypto.randomBytes(102400000);
const ALGORITHM = "aes-256-cbc";
const DEFAULT_PASSWORD = process.env.PASSWORD || "senha-forte";

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
    const key = crypto.scryptSync(password, SALT, 32, { N: 2 });
    const iv = crypto.randomBytes(16);

    const input = fs.createReadStream(inputPath);
    const output = fs.createWriteStream(outputPath);

    output.write(iv, (err) => {
      if (err) return reject(err);
      const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
      input.pipe(cipher).pipe(output, { end: true });
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
    const key = crypto.scryptSync(password, SALT, 32);
    // Lê o IV de forma síncrona antes de criar o stream
    const fd = fs.openSync(inputPath, "r");
    const ivBuffer = Buffer.alloc(16);
    fs.readSync(fd, ivBuffer, 0, 16, 0);
    fs.closeSync(fd);
    const decipher = crypto.createDecipheriv(ALGORITHM, key, ivBuffer);
    const input = fs.createReadStream(inputPath, { start: 16 });
    const output = fs.createWriteStream(outputPath);
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
