class Oe < Formula
  desc "Command-line tools for OpenE2EE projects"
  homepage "https://github.com/open-e2ee/oe"
  url "https://github.com/open-e2ee/oe/archive/refs/tags/v3.8.7.tar.gz"
  sha256 "093ed9d5d2c2f8cd12b4508dd26b6c03f1148e254b466311c6104c2c6f139e7f"
  license "Apache-2.0"
  head "https://github.com/open-e2ee/oe.git", branch: "main"

  depends_on "go" => :build

  def install
    system "go", "build", *std_go_args(ldflags: "-X main.version=#{version}"), "./cmd/oe"
  end

  test do
    assert_match "\"command\":\"version\"", shell_output("#{bin}/oe --json version")
  end
end
