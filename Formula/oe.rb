class Oe < Formula
  desc "Command-line tools for OpenE2EE projects"
  homepage "https://github.com/open-e2ee/oe"
  url "https://github.com/open-e2ee/oe/archive/refs/tags/v3.8.3.tar.gz"
  sha256 "cbb0bedede54da53dee1feb9682f3a2eaf5933aebcb050532f19a5cc0ae91846"
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
