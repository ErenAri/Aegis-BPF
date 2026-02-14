// cppcheck-suppress-file missingIncludeSystem
#include "cli_policy.hpp"

#include <fstream>
#include <string>

#include "cli_common.hpp"
#include "commands_policy.hpp"

namespace aegis {

int dispatch_policy_command(int argc, char** argv, const char* prog)
{
    if (argc < 3)
        return usage(prog);
    std::string sub = argv[2];

    if (sub == "lint") {
        if (argc < 4)
            return usage(prog);
        bool fix = false;
        std::string out_path;
        for (int i = 4; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--fix") {
                fix = true;
            } else if (arg == "--out") {
                if (i + 1 >= argc)
                    return usage(prog);
                out_path = argv[++i];
            } else {
                return usage(prog);
            }
        }
        if (fix) {
            return cmd_policy_lint_fix(argv[3], out_path);
        }
        if (!out_path.empty()) {
            return usage(prog);
        }
        return cmd_policy_lint(argv[3]);
    }

    if (sub == "validate") {
        if (argc < 4)
            return usage(prog);
        bool verbose = false;
        for (int i = 4; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--verbose" || arg == "-v") {
                verbose = true;
            } else {
                return usage(prog);
            }
        }
        return cmd_policy_validate(argv[3], verbose);
    }

    if (sub == "apply") {
        if (argc < 4)
            return usage(prog);
        bool reset = false;
        bool rollback_on_failure = true;
        bool require_signature = false;
        bool dry_run = false;
        uint32_t canary_seconds = 0;
        uint32_t canary_threshold = 10;
        std::string sha256;
        std::string sha256_file;

        for (int i = 4; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--reset") {
                reset = true;
            } else if (arg == "--no-rollback") {
                rollback_on_failure = false;
            } else if (arg == "--require-signature") {
                require_signature = true;
            } else if (arg == "--dry-run") {
                dry_run = true;
            } else if (arg.rfind("--canary=", 0) == 0) {
                canary_seconds = static_cast<uint32_t>(std::stoul(arg.substr(9)));
            } else if (arg.rfind("--canary-threshold=", 0) == 0) {
                canary_threshold = static_cast<uint32_t>(std::stoul(arg.substr(19)));
            } else if (arg == "--sha256") {
                if (i + 1 >= argc)
                    return usage(prog);
                sha256 = argv[++i];
            } else if (arg == "--sha256-file") {
                if (i + 1 >= argc)
                    return usage(prog);
                sha256_file = argv[++i];
            } else {
                return usage(prog);
            }
        }

        if (dry_run) {
            return cmd_policy_dry_run(argv[3], sha256, sha256_file);
        }

        if (canary_seconds > 0) {
            return cmd_policy_canary(argv[3], reset, sha256, sha256_file, rollback_on_failure, canary_seconds,
                                     canary_threshold);
        }

        std::ifstream check_file(argv[3]);
        std::string first_line;
        std::getline(check_file, first_line);
        if (first_line.starts_with("AEGIS-POLICY-BUNDLE") || require_signature) {
            return cmd_policy_apply_signed(argv[3], require_signature);
        }
        return cmd_policy_apply(argv[3], reset, sha256, sha256_file, rollback_on_failure);
    }

    if (sub == "sign") {
        if (argc < 4)
            return usage(prog);
        std::string key_path;
        std::string output_path;
        for (int i = 4; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--key") {
                if (i + 1 >= argc)
                    return usage(prog);
                key_path = argv[++i];
            } else if (arg == "--output") {
                if (i + 1 >= argc)
                    return usage(prog);
                output_path = argv[++i];
            } else {
                return usage(prog);
            }
        }
        if (key_path.empty() || output_path.empty())
            return usage(prog);
        return cmd_policy_sign(argv[3], key_path, output_path);
    }

    if (sub == "export") {
        if (argc != 4)
            return usage(prog);
        return cmd_policy_export(argv[3]);
    }

    if (sub == "show") {
        if (argc != 3)
            return usage(prog);
        return cmd_policy_show();
    }

    if (sub == "rollback") {
        if (argc != 3)
            return usage(prog);
        return cmd_policy_rollback();
    }

    return usage(prog);
}

} // namespace aegis
