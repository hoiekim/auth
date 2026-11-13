// The break-glass CLI (docs/DESIGN.md §9.6), run inside a running auth
// container: `bun cli.ts help`.
import { main } from "./src/cli";

process.exit(await main(process.argv.slice(2)));
