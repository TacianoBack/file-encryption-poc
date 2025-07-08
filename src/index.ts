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

function createSafeHandlers(
  output: fs.WriteStream,
  resolve: () => void,
  reject: (err: any) => void
) {
  let finished = false;
  function safeFinish() {
    if (!finished) {
      finished = true;
      output.close();
      resolve();
    }
  }
  function safeReject(err: any) {
    if (!finished) {
      finished = true;
      output.close();
      reject(err);
    }
  }
  return { safeFinish, safeReject };
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
    const { safeFinish, safeReject } = createSafeHandlers(
      output,
      resolve,
      reject
    );
    // Escreve salt + IV no início do arquivo
    output.write(Buffer.concat([salt, iv]), (err) => {
      if (err) return safeReject(err);
      input.pipe(cipher).pipe(output, { end: false });
      cipher.on("end", () => {
        // Escreve o authentication tag ao final do arquivo
        output.write(cipher.getAuthTag(), (err2) => {
          if (err2) return safeReject(err2);
          output.end();
        });
      });
      output.on("finish", safeFinish);
      output.on("error", safeReject);
      input.on("error", safeReject);
      cipher.on("error", safeReject);
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
    const { safeFinish, safeReject } = createSafeHandlers(
      output,
      resolve,
      reject
    );
    input.pipe(decipher).pipe(output);
    output.on("finish", safeFinish);
    output.on("error", safeReject);
    input.on("error", safeReject);
    decipher.on("error", safeReject);
  });
}

export interface FileEncryptor {
  encrypt(
    inputPath: string,
    outputPath: string,
    password: string
  ): Promise<void>;
  decrypt(
    inputPath: string,
    outputPath: string,
    password: string
  ): Promise<void>;
}

export class AESGCMFileEncryptor implements FileEncryptor {
  encrypt(
    inputPath: string,
    outputPath: string,
    password: string
  ): Promise<void> {
    return encryptFile({ inputPath, outputPath, password });
  }
  decrypt(
    inputPath: string,
    outputPath: string,
    password: string
  ): Promise<void> {
    return decryptFile({ inputPath, outputPath, password });
  }
}

export function getDefaultEncryptor(): FileEncryptor {
  return new AESGCMFileEncryptor();
}

if (String(process.env?.TEST) !== "true") {
  const encryptor = getDefaultEncryptor();
  const inputPath = process.env.INPUT_FILE || "./test-file.zip";
  const outputPath = process.env.OUTPUT_FILE || "./test-file.zip.enc";
  const decryptedOutputPath =
    process.env.DECRYPTED_FILE || "./test-file-decrypted.zip";
  encryptor
    .encrypt(inputPath, outputPath, DEFAULT_PASSWORD)
    .then(() => {
      console.log("Arquivo criptografado com sucesso:", outputPath);
      return encryptor.decrypt(
        outputPath,
        decryptedOutputPath,
        DEFAULT_PASSWORD
      );
    })
    .then(() => {
      console.log("Arquivo descriptografado com sucesso:", decryptedOutputPath);
    })
    .catch((err) => {
      console.error("Erro ao criptografar/descriptografar o arquivo:", err);
    });
}
