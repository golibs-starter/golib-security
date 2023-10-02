package golibsecTestUtil

import (
	"github.com/golibs-starter/golib"
	"go.uber.org/fx"
)

func JwtTestUtilOpt() fx.Option {
	return fx.Options(
		golib.ProvideProps(NewJwtTestProperties),
		fx.Provide(NewJwtTestUtil),
	)
}
