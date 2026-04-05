import { readFile } from 'node:fs/promises';

export async function loadFixture<T>(relativePath: string): Promise<T> {
  const fileUrl = new URL(`../fixtures/${relativePath}`, import.meta.url);
  return JSON.parse(await readFile(fileUrl, 'utf8')) as T;
}

