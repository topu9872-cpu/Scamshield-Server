import { MongoClient } from "mongodb";
import dotenv from "dotenv";

dotenv.config();

const client = new MongoClient(process.env.MONGODB_URI!, {
  connectTimeoutMS: 5000,
  serverSelectionTimeoutMS: 5000,
});

async function test() {
  try {
    console.log("Connecting...");
    await client.connect();
    console.log("Connected!");
  } catch (err) {
    console.error(err);
  } finally {
    await client.close();
  }
}

test();