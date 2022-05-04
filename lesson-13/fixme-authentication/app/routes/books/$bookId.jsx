import { useLoaderData, useCatch } from "@remix-run/react";
import { json } from "@remix-run/node";
import connectDb from "~/db/connectDb.server.js";
import { requireUserSession } from "../../sessions.server";

export async function loader({ params, request }) {
  const db = await connectDb();
  const book = await db.models.Book.findById(params.bookId);
  if (!book) {
    throw new Response(`Couldn't find book with id ${params.bookId}`, {
      status: 404,
    });
  }
  // Verify that the book belongs to the currently logged in user, otherwise throw a 403 error
  const session = await requireUserSession(request);
  const userId = session.get("userId");
  const verifyUser = userId == book.userId;
  if (!verifyUser) {
    throw new Response(`This book doesnt belong to you :) ${params.bookId}`, {
      status: 403,
    });
  } else {
    return json(book);
  }
}

export default function BookPage() {
  const book = useLoaderData();
  return (
    <div>
      <h1 className="text-2xl font-bold mb-4">{book.title}</h1>
      <code>
        <pre>{JSON.stringify(book, null, 2)}</pre>
      </code>
    </div>
  );
}

export function CatchBoundary() {
  const caught = useCatch();
  return (
    <div>
      <h1>
        {caught.status} {caught.statusText}
      </h1>
      <h2>{caught.data}</h2>
    </div>
  );
}

export function ErrorBoundary({ error }) {
  return (
    <h1 className="text-red-500 font-bold">
      {error.name}: {error.message}
    </h1>
  );
}
