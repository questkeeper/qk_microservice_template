import { Context } from "hono";
import { supabase } from "@/utils/initSupabase";
import jwt from "@tsndr/cloudflare-worker-jwt";

async function jwtMiddleware(
  c: Context<{}, any, {}>,
  next: () => Promise<any>
) {
  // Check for the Authorization header
  const authHeader = c.req.header("Authorization");

  // Ensure the Authorization header is present and in the correct format
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    c.status(401);
    return c.json({ error: "Invalid bearer token" });
  }

  // Ensure Supabase is initialized
  if (supabase === null) {
    c.status(500);
    return c.json({ error: "Supabase not initialized" });
  }

  // Extract the token from the Authorization header
  const token = authHeader.split(" ")[1];
  const { SUPABASE_JWT_SECRET } = c.env as { SUPABASE_JWT_SECRET: string };

  try {
    // Verify the JWT token
    const decoded = await jwt.verify(token, SUPABASE_JWT_SECRET);

    if (!decoded) {
      c.status(401);
      return c.json({ error: "Unauthorized" });
    }

    // Decode the token to access its payload
    const value = jwt.decode(token);

    // Check if the token is expired
    if (value.payload?.exp && value.payload.exp < Date.now() / 1000) {
      c.status(401);
      return c.json({ error: "Token expired" });
    }

    // Fetch user data from Supabase using the token
    const { data, error } = await supabase.auth.getUser(token);

    if (!data || error) {
      c.status(401);
      return c.json({ error: "Invalid user" });
    }

    // Ensure the user ID in the token matches the one from Supabase
    if (value.payload?.sub !== data?.user.id) {
      c.status(401);
      return c.json({ error: "Invalid user" });
    }

    // Add the user to the context
    const key = "user" as never;
    c.set(key, data.user); // In other functions, you can access the user with c.get("user")

    // Proceed to the next middleware or route handler
    return next();
  } catch (error) {
    c.status(401);
    return c.json({ error: "Unauthorized" });
  }
}

export default jwtMiddleware;
