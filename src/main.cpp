// cppcheck-suppress-file missingIncludeSystem
/*
 * AegisBPF - eBPF-based runtime security agent
 *
 * Main entry point.
 */

#include "cli_dispatch.hpp"

int main(int argc, char** argv)
{
    return aegis::dispatch_cli(argc, argv);
}
