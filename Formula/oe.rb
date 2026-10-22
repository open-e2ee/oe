class Oe < Formula
  desc "Command-line tools for OpenE2EE projects"
  homepage "https://github.com/open-e2ee/oe"
  url "https://github.com/open-e2ee/oe/archive/refs/tags/v3.5.0.tar.gz"
  sha256 "776a74f5b631110ef499f8032b0a8dc8d61ca7a7fd2e7eff4df7381e05fdc758"
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
