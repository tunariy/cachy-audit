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
sha256sums=('35e8bfa4d9ee8a64f382b10e3965c8c4c9e178e2acff36b7d4a323a4296571bd')

build() {
  cmake -B build -S "$pkgname-$pkgver" -DCMAKE_BUILD_TYPE=Release
  cmake --build build
}

package() {
  DESTDIR="$pkgdir" cmake --install build
  install -Dm644 "$pkgname-$pkgver/LICENSE" -t "$pkgdir/usr/share/licenses/$pkgname/"
}
