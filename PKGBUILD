pkgname=cachy-audit
pkgver=1.0.0
pkgrel=1
pkgdesc="A fast, CachyOS-specific package vulnerability auditor"
arch=('x86_64')
url="https://github.com/tunariy/cachy-audit"
license=('MIT')
depends=('curl' 'pacman' 'glibc' 'gcc-libs')
makedepends=('cmake' 'nlohmann-json')
source=("$pkgname-$pkgver.tar.gz::$url/archive/refs/tags/v$pkgver.tar.gz")
sha256sums=('b579a64dab67da9feb2dcbdffe5f5fe63549ed4efb6efd14d5d4435f53d6e545')

build() {
  cmake -B build -S "$pkgname-$pkgver" -DCMAKE_BUILD_TYPE=Release
  cmake --build build
}

package() {
  DESTDIR="$pkgdir" cmake --install build
  install -Dm644 "$pkgname-$pkgver/LICENSE" -t "$pkgdir/usr/share/licenses/$pkgname/"
}
