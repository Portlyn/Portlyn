import ClientPage from "./client";

export function generateStaticParams() {
  return [{ id: "_" }];
}

export const dynamicParams = false;

export default function Page() {
  return <ClientPage />;
}
