import { Context } from "hono";
import { supabase } from "@/utils/initSupabase";
import jwt from "@tsndr/cloudflare-worker-jwt";

const CACHE_TTL = 55 * 60; // 55 minutes

async function jwtMiddleware(
  c: Context<{}, any, {}>,
  next: () => Promise<any>
) {
  const authHeader = c.req.header("Authorization");

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    c.status(401);
    return c.json({ error: "Unauthorized" });
  }

  if (supabase === null) {
    c.status(500);
    return c.json({ error: "Supabase not initialized" });
  }

  const token = authHeader.split(" ")[1];
  const { SUPABASE_JWT_SECRET } = c.env as { SUPABASE_JWT_SECRET: string };

  try {
    // Verify the token first
    const decoded = await jwt.verify(token, SUPABASE_JWT_SECRET);

    if (!decoded) {
      c.status(401);
      return c.json({ error: "Invalid token" });
    }

    // Decode the token to access its payload
    const value = jwt.decode(token);
    const userId = value.payload?.sub; // User ID

    if (!userId) {
      c.status(401);
      return c.json({ error: "Invalid token payload" });
    }

    // Check cache
    const cache = caches.default;
    const cacheKey = `${c.req.url}::users-${userId}`;
    const cachedResponse = await cache.match(cacheKey); // Check if user is in cache already
    const userKey = "user" as never;

    if (cachedResponse) {
      const cachedUser = await cachedResponse.json();
      c.set(userKey, cachedUser);
      return next();
    }

    // If not in cache, fetch user data from Supabase
    const { data, error } = await supabase.auth.getUser(token);

    if (!data || error) {
      c.status(401);
      return c.json({ error: "User not found" });
    }

    if (userId !== data?.user.id) {
      c.status(401);
      return c.json({ error: "Token mismatch" });
    }

    // Cache the user data
    const cacheResponse = new Response(JSON.stringify(data.user));
    cacheResponse.headers.set("Cache-Control", `max-age=${CACHE_TTL}`);
    await cache.put(cacheKey, cacheResponse);

    // Add the user to the context
    c.set(userKey, data.user);

    return next();
  } catch (error) {
    c.status(401);
    return c.json({ error: "Unauthorized" });
  }
}

export default jwtMiddleware;
