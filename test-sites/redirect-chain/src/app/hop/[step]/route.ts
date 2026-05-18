import type { NextRequest } from "next/server";
import { absoluteFixtureUrl, redirectResponse } from "@/lib/redirects";

type RouteContext = {
  params: Promise<{
    step: string;
  }>;
};

export async function GET(request: NextRequest, context: RouteContext) {
  const { step } = await context.params;
  const nextPath = step === "1" ? "/hop/2" : "/final/safe";

  return await redirectResponse(absoluteFixtureUrl(request, nextPath));
}

export const HEAD = GET;
