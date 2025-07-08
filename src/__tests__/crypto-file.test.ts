import { encryptFile, decryptFile } from "../index";
import * as fs from "fs";
import * as path from "path";

describe("Crypto File", () => {
  const inputPath = path.join(__dirname, "test.txt");
  const encryptedPath = path.join(__dirname, "test.txt.enc");
  const decryptedPath = path.join(__dirname, "test-decrypted.txt");
  const password = "jest-password";

  beforeAll(() => {
    fs.writeFileSync(inputPath, "conteudo de teste");
  });

  afterAll(() => {
    [inputPath, encryptedPath, decryptedPath].forEach((file) => {
      if (fs.existsSync(file)) fs.unlinkSync(file);
    });
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
});
