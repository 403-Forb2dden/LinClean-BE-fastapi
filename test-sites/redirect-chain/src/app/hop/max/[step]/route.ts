import type { NextRequest } from "next/server";
import {
  MAX_HOP_TERMINAL_STEP,
  absoluteFixtureUrl,
  redirectResponse,
} from "@/lib/redirects";

type RouteContext = {
  params: Promise<{
    step: string;
  }>;
};

export async function GET(request: NextRequest, context: RouteContext) {
  const { step } = await context.params;
  const currentStep = Number.parseInt(step, 10);
  const nextStep = Number.isFinite(currentStep) ? currentStep + 1 : 1;
  const nextPath =
    nextStep > MAX_HOP_TERMINAL_STEP
      ? "/final/safe"
      : `/hop/max/${nextStep}`;

  return await redirectResponse(absoluteFixtureUrl(request, nextPath));
}

export const HEAD = GET;
