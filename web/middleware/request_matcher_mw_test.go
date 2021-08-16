package middleware

import "testing"

func Test_containsOrStartsString(t *testing.T) {
	type args struct {
		slice  []string
		needle string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Test returns true when contains",
			args: args{
				slice:  []string{"/info", "/health", "/docs/*"},
				needle: "/health",
			},
			want: true,
		},
		{
			name: "Test returns true when starts",
			args: args{
				slice:  []string{"/docs/*"},
				needle: "/docs/index.html",
			},
			want: true,
		},
		{
			name: "Test returns true when has an element starts all",
			args: args{
				slice:  []string{"*"},
				needle: "/docs/index.html",
			},
			want: true,
		},
		{
			name: "Test returns true when slice no matched and has empty value",
			args: args{
				slice:  []string{"", "/docs/*"},
				needle: "/docs/index.html",
			},
			want: true,
		},
		{
			name: "Test returns false when no element matched",
			args: args{
				slice:  []string{"info"},
				needle: "/docs/index.html",
			},
			want: false,
		},
		{
			name: "Test returns false when no elements",
			args: args{
				slice:  []string{},
				needle: "/docs/index.html",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsOrStartsString(tt.args.slice, tt.args.needle); got != tt.want {
				t.Errorf("containsOrStartsString() = %v, want %v", got, tt.want)
			}
		})
	}
}
