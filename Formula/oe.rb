class Oe < Formula
  desc "Command-line tools for OpenE2EE projects"
  homepage "https://github.com/open-e2ee/oe"
  url "https://github.com/open-e2ee/oe/archive/refs/tags/v3.1.1.tar.gz"
  sha256 "e3df5b3a514fdd2654cb9f4187f335babaf147062a0bcb03e783c14e0f95fcea"
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
