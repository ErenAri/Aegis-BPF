package console

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"time"
)

//go:embed static/*
var staticFiles embed.FS

//go:embed templates/*.html templates/partials/*.html
var templateFiles embed.FS

// funcMap provides template helper functions.
var funcMap = template.FuncMap{
	"timeAgo": func(t *time.Time) string {
		if t == nil {
			return "never"
		}
		d := time.Since(*t)
		switch {
		case d < time.Minute:
			return "just now"
		case d < time.Hour:
			m := int(d.Minutes())
			if m == 1 {
				return "1 minute ago"
			}
			return fmt.Sprintf("%d minutes ago", m)
		case d < 24*time.Hour:
			h := int(d.Hours())
			if h == 1 {
				return "1 hour ago"
			}
			return fmt.Sprintf("%d hours ago", h)
		default:
			days := int(d.Hours()) / 24
			if days == 1 {
				return "1 day ago"
			}
			return fmt.Sprintf("%d days ago", days)
		}
	},
	"truncHash": func(hash string) string {
		if len(hash) > 12 {
			return hash[:12]
		}
		return hash
	},
	"badgeClass": func(phase string) string {
		switch phase {
		case "Applied":
			return "bg-green-500/20 text-green-400 border-green-500/30"
		case "Error":
			return "bg-red-500/20 text-red-400 border-red-500/30"
		case "Pending":
			return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
		default:
			return "bg-gray-500/20 text-gray-400 border-gray-500/30"
		}
	},
	"modeClass": func(mode string) string {
		switch mode {
		case "enforce":
			return "bg-red-500/20 text-red-400 border-red-500/30"
		case "audit":
			return "bg-blue-500/20 text-blue-400 border-blue-500/30"
		default:
			return "bg-gray-500/20 text-gray-400 border-gray-500/30"
		}
	},
	"actionClass": func(action string) string {
		switch action {
		case "Allow":
			return "bg-green-500/20 text-green-400"
		case "Block":
			return "bg-red-500/20 text-red-400"
		default:
			return "bg-gray-500/20 text-gray-400"
		}
	},
	"conditionIcon": func(status string) string {
		switch status {
		case "True":
			return "text-green-400"
		case "False":
			return "text-red-400"
		default:
			return "text-yellow-400"
		}
	},
}

// TemplateSet holds per-page template clones so that each page's
// {{define "content"}} block doesn't collide with others.
type TemplateSet struct {
	pages map[string]*template.Template
}

// Lookup returns the template set for a given page name.
func (ts *TemplateSet) Lookup(page string) *template.Template {
	return ts.pages[page]
}

var pageFiles = []string{
	"dashboard",
	"policies",
	"policy_detail",
	"nodes",
}

func parseTemplates() (*TemplateSet, error) {
	// Parse shared base: layout + all partials.
	base, err := template.New("").Funcs(funcMap).ParseFS(
		templateFiles,
		"templates/layout.html",
		"templates/partials/*.html",
	)
	if err != nil {
		return nil, fmt.Errorf("parsing base templates: %w", err)
	}

	ts := &TemplateSet{pages: make(map[string]*template.Template, len(pageFiles))}
	for _, page := range pageFiles {
		clone, err := base.Clone()
		if err != nil {
			return nil, fmt.Errorf("cloning base for %s: %w", page, err)
		}
		_, err = clone.ParseFS(templateFiles, "templates/"+page+".html")
		if err != nil {
			return nil, fmt.Errorf("parsing %s.html: %w", page, err)
		}
		ts.pages[page] = clone
	}
	return ts, nil
}

func staticFS() (fs.FS, error) {
	return fs.Sub(staticFiles, "static")
}

// PreviewAssets returns parsed templates and the static FS for the
// console-preview development server. Not used in production.
func PreviewAssets() (*TemplateSet, fs.FS) {
	ts, err := parseTemplates()
	if err != nil {
		panic("console: parse templates: " + err.Error())
	}
	sub, err := staticFS()
	if err != nil {
		panic("console: static fs: " + err.Error())
	}
	return ts, sub
}
