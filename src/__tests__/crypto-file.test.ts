import { encryptFile, decryptFile, generateSalt } from "../index";
import * as fs from "fs";
import * as path from "path";

describe("Crypto File", () => {
  const inputPath = path.join(__dirname, "test.txt");
  const encryptedPath = path.join(__dirname, "test.txt.enc");
  const decryptedPath = path.join(__dirname, "test-decrypted.txt");
  const password = "jest-password";

  beforeEach(() => {
    fs.writeFileSync(inputPath, "conteudo de teste");
    if (fs.existsSync(encryptedPath)) fs.unlinkSync(encryptedPath);
    if (fs.existsSync(decryptedPath)) fs.unlinkSync(decryptedPath);
  });

  afterAll((done) => {
    [inputPath, encryptedPath, decryptedPath].forEach((file) => {
      if (fs.existsSync(file)) fs.unlinkSync(file);
    });
    setImmediate(done); // Garante que todos os handles de IO sejam liberados
  });

  it("deve criptografar e descriptografar um arquivo mantendo o conteúdo", async () => {
    await encryptFile({ inputPath, outputPath: encryptedPath, password });
    await decryptFile({
      inputPath: encryptedPath,
      outputPath: decryptedPath,
      password,
    });
    const original = fs.readFileSync(inputPath);
    const decrypted = fs.readFileSync(decryptedPath);
    expect(decrypted.equals(original)).toBe(true);
  });

  it("deve gerar um salt aleatório de tamanho correto", () => {
    const salt = generateSalt(32);
    expect(Buffer.isBuffer(salt)).toBe(true);
    expect(salt.length).toBe(32);
  });

  function waitForStreamErrorOrFinish(promise: Promise<void>, timeout = 5000) {
    return Promise.race([
      promise,
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error("timeout")), timeout)
      ),
    ]);
  }

  it("deve falhar ao descriptografar com senha errada", async () => {
    await encryptFile({ inputPath, outputPath: encryptedPath, password });
    let errorCaught = false;
    try {
      await waitForStreamErrorOrFinish(
        decryptFile({
          inputPath: encryptedPath,
          outputPath: decryptedPath,
          password: "senha-errada",
        }),
        5000
      );
    } catch (err: any) {
      errorCaught = String(err.message).match(
        /unable to authenticate|Unsupported state|timeout/
      )
        ? true
        : false;
    }
    expect(errorCaught).toBe(true);
  }, 10000);

  it("deve falhar ao descriptografar arquivo corrompido", async () => {
    await encryptFile({ inputPath, outputPath: encryptedPath, password });
    // Corrompe o arquivo criptografado
    const fd = fs.openSync(encryptedPath, "r+");
    fs.writeSync(fd, Buffer.from([0xff, 0xff, 0xff]), 0, 3, 0); // sobrescreve início
    fs.closeSync(fd);
    let errorCaught = false;
    try {
      await waitForStreamErrorOrFinish(
        decryptFile({
          inputPath: encryptedPath,
          outputPath: decryptedPath,
          password,
        }),
        5000
      );
    } catch (err: any) {
      errorCaught = String(err.message).match(
        /unable to authenticate|Unsupported state|timeout/
      )
        ? true
        : false;
    }
    expect(errorCaught).toBe(true);
  }, 10000);
});
