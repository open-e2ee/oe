#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "$0")/.." && pwd)
temp_base=${TMPDIR:-/tmp}
temp_base=${temp_base%/}
test_root=$(mktemp -d "$temp_base/oe-homebrew.XXXXXX")
tap_name="open-e2ee/oe-local-$$"

cleanup() {
  brew uninstall --formula --force --ignore-dependencies "$tap_name/oe" >/dev/null 2>&1 || true
  brew untap --force "$tap_name" >/dev/null 2>&1 || true
  if [[ -n "$test_root" && "$test_root" == "$temp_base"/oe-homebrew.* ]]; then
    rm -r "$test_root"
  fi
}
trap cleanup EXIT

brew tap-new --no-git "$tap_name"
tap_root=$(brew --repository "$tap_name")
cp "$repository_root/Formula/oe.rb" "$tap_root/Formula/oe.rb"
brew audit --strict "$tap_name/oe"
HOMEBREW_NO_AUTO_UPDATE=1 brew fetch --force "$tap_name/oe"

# shellcheck disable=SC2016
published_version=$(ruby -ne 'puts Regexp.last_match(1) if %r{refs/tags/v([^/]+)\.tar\.gz}.match($_)' "$tap_root/Formula/oe.rb")
test -n "$published_version"
HOMEBREW_NO_AUTO_UPDATE=1 brew install "$tap_name/oe"
brew test "$tap_name/oe"
published_binary="$(brew --prefix "$tap_name/oe")/bin/oe"
published_result=$("$published_binary" --json version)
ruby -rjson -e 'abort "unexpected oe version" unless JSON.parse(ARGV[0]).dig("data", "version") == ARGV[1]' "$published_result" "$published_version"
root_help=$(COLUMNS=80 "$published_binary" --agent no -h)
group_help=$(COLUMNS=80 "$published_binary" --agent no help project)
leaf_help=$(COLUMNS=80 "$published_binary" --agent no project usage --help)
for rendered in "$root_help" "$group_help" "$leaf_help"; do
  printf '%s\n' "$rendered" | awk 'length($0) > 80 { failed = 1 } END { exit failed }'
done
[[ "$root_help" == *"Global flags"* && "$root_help" == *"Exit codes"* && "$root_help" == *"Environment variables"* ]]
[[ "$group_help" == *"oe project"* && "$leaf_help" == *"oe project usage"* ]]
# Compare machine help with the captured pre-change contract.
ruby -rjson -ropen3 -e '
  rows = JSON.parse(File.read(ARGV[0]))
  { "bare help" => ["--json", "help"], "project --help" => ["--json", "project", "--help"] }.each do |name, args|
    expected = rows.find { |row| row["mode"] == "json" && row["name"] == name }.fetch("stdout")
    output, error, status = Open3.capture3(ARGV[1], *args)
    abort "unexpected JSON help for #{name}: #{error}" unless status.success? && error.empty? && output == expected
  end
' "$repository_root/internal/app/testdata/cli_contract.json" "$published_binary"
brew uninstall --formula --ignore-dependencies "$tap_name/oe"

tar \
  --exclude=.git \
  --exclude=bin \
  --exclude=dist \
  --exclude=node_modules \
  --exclude=.release \
  -czf "$test_root/oe-0.1.0.tar.gz" \
  -C "$repository_root" .
checksum=$(shasum -a 256 "$test_root/oe-0.1.0.tar.gz" | awk '{print $1}')

# shellcheck disable=SC2016
OE_FORMULA_URL="file://$test_root/oe-0.1.0.tar.gz" \
OE_FORMULA_SHA256="$checksum" \
ruby -pi -e '
  if $_.start_with?(%q{  url })
    $_ = "  url \"#{ENV.fetch("OE_FORMULA_URL")}\"\n  version \"0.1.0\"\n"
  elsif $_.start_with?(%q{  sha256 })
    $_ = "  sha256 \"#{ENV.fetch("OE_FORMULA_SHA256")}\"\n"
  end
' "$tap_root/Formula/oe.rb"

HOMEBREW_NO_AUTO_UPDATE=1 brew install "$tap_name/oe"
brew test "$tap_name/oe"
