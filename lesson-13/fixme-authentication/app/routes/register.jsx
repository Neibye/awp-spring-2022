import { json, redirect } from "@remix-run/node";
import { Form, Link, useActionData } from "@remix-run/react";
import bcrypt from "bcryptjs";
import { getSession, commitSession } from "~/sessions.server.js";
import connectDb from "~/db/connectDb.server.js";
import { requireUserSession } from "../sessions.server";

export async function action({ request }) {
  /* Connecting to the database. */
  const db = await connectDb();

  /* Getting the session from the cookie. */
  const session = await getSession(request.headers.get("Cookie"));

  /* Getting the form data from the request. */
  const form = await request.formData();

  if (form.get("password").trim() !== form.get("repeatPassword").trim()) {
    // Return a json response with an "errorMessage" about the password not matching. Status 400?
    return json(
      {
        errorMessage: "Passwords doesnt match",
        values: Object.fromEntries(form),
      },
      { status: 400 }
    );
  }

  if (form.get("password").trim()?.length < 8) {
    // Return a json response with an "errorMessage" about the password length. Status 400?
    return json(
      {
        errorMessage: "Atleast 8 characters",
        values: Object.fromEntries(form),
      },
      { status: 400 }
    );
  }

  const hashedPassword = await bcrypt.hash(form.get("password").trim(), 10);

  try {
    const user = await db.models.User.create({
      username: form.get("username").trim(),
      password: hashedPassword,
    });
    if (user) {
      // Return a redirect to the home page which sets a cookie that commits the session
      session.set("userId", user._id);
      return redirect(`/`, {
        headers: {
          "Set-Cookie": await commitSession(session),
        },
      });
    } else {
      return json(
        { errorMessage: "User couldn't be created" },
        { status: 400 }
      );
    }
  } catch (error) {
    return json(
      {
        errorMessage:
          error.message ??
          error.errors?.map((error) => error.message).join(", "),
      },
      { status: 400 }
    );
  }
}

export async function loader({ request }) {
  // Check if the session has a userId, and if so; redirect to the homepage
  await requireUserSession(request);
  return null;
}

export default function Register() {
  const actionData = useActionData();

  return (
    <div className="m-3">
      <h2>Register</h2>
      {actionData?.errorMessage ? (
        <p className="text-red-500 font-bold my-3">{actionData.errorMessage}</p>
      ) : null}
      <Form method="post" className="text-inherit">
        <Input
          type="text"
          name="username"
          id="username"
          placeholder="Username"
        />
        <Input
          type="password"
          name="password"
          id="password"
          placeholder="Password"
        />
        <Input
          type="password"
          name="repeatPassword"
          id="repeatPassword"
          placeholder="Repeat password"
        />
        <div className="flex flex-row items-center gap-3">
          <button type="submit" className="my-3 p-2 border rounded">
            Sign up
          </button>
          <span className="italic">or</span>
          <Link to="/login" className="underline">
            Log in
          </Link>
        </div>
      </Form>
    </div>
  );
}

function Input({ ...rest }) {
  return (
    <input
      {...rest}
      className="block my-3 border rounded px-2 py-1 w-full lg:w-1/2 bg-white border-zinc-300"
    />
  );
}
