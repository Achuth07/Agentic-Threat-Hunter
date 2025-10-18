# Responsive Design - Quick Reference

## Mobile View (< 1024px)

### Key Changes
```
┌─────────────────────┐
│ [☰] AI Threat Hunt  │ ← Hamburger menu + title
│                     │
│  ┌───────────────┐  │
│  │               │  │ ← Chat messages
│  │  Full width   │  │   (stacked vertically)
│  │               │  │
│  └───────────────┘  │
│                     │
│  [Input field...]   │ ← Full width input
│  [Send]             │
└─────────────────────┘
```

**Features:**
- Sidebar hidden by default (slides in when hamburger clicked)
- Full-width content area
- Vertical stacking of all elements
- Smaller text and padding
- Simplified button labels ("New" instead of "New Threat Hunt")

## Tablet View (768px - 1023px)

### Key Changes
```
┌──────┬──────────────────┐
│      │ AI Threat Hunting│ ← Sidebar visible
│ Nav  │                  │
│      │  ┌────┐  ┌────┐  │ ← 2-column grid
│      │  │Card│  │Card│  │   for dashboard
│      │  └────┘  └────┘  │
│      │                  │
│      │  [Input........ ]│ ← Medium width
│      │  [Send]          │
└──────┴──────────────────┘
```

**Features:**
- Sidebar visible but collapsible
- 2-column grid layouts (dashboard, integrations)
- Medium-sized text and padding
- Most features visible

## Desktop View (≥ 1024px)

### Key Changes
```
┌──────────┬───────────────────────────┐
│          │ AI Threat Hunting         │
│  Brand   │                           │
│          │ ┌───┐ ┌───┐ ┌───┐ ┌───┐  │ ← 4-column grid
│  Nav     │ │ 1 │ │ 2 │ │ 3 │ │ 4 │  │
│  Items   │ └───┘ └───┘ └───┘ └───┘  │
│          │                           │
│          │ ┌─────────────────────┐   │
│  Docs    │ │ Content Area        │   │ ← Full features
│  List    │ └─────────────────────┘   │
│          │                           │
│  [More]  │ [Input field............] │ ← Wider input
│          │ [Send Message]            │
└──────────┴───────────────────────────┘
```

**Features:**
- Full sidebar always visible
- 4-column grid layouts
- Larger text and generous padding
- All labels and descriptions visible
- Optimal spacing and layout

## Responsive Breakpoints

| Screen Size | Width Range | Layout |
|-------------|-------------|--------|
| Mobile | < 640px | 1 column, hidden sidebar |
| Small Tablet | 640px - 767px | 1-2 columns, toggle sidebar |
| Tablet | 768px - 1023px | 2 columns, visible sidebar |
| Desktop | 1024px - 1279px | 2-4 columns, full sidebar |
| Large Desktop | ≥ 1280px | 4 columns, expanded layout |

## Mobile Menu Interaction

### Closed State (Default)
```
┌─────────────────────┐
│ [☰] Page Title      │ ← Click hamburger to open
│                     │
│ Content area        │
│                     │
└─────────────────────┘
```

### Open State
```
┌────────┬────────────┐
│        │ [backdrop] │ ← Dark overlay
│ Nav    │            │   Click to close
│        │            │
│ Items  │            │
│        │            │
└────────┴────────────┘
    ↑
    Slides in from left
```

## Common Patterns

### Responsive Text
```jsx
className="text-xs lg:text-sm"      // Small → Regular
className="text-sm lg:text-base"    // Regular → Large  
className="text-lg lg:text-2xl"     // Large → Extra Large
```

### Responsive Padding
```jsx
className="px-4 lg:px-8"            // Less → More horizontal
className="py-4 lg:py-6"            // Less → More vertical
className="p-4 lg:p-6"              // Less → More all sides
```

### Responsive Spacing
```jsx
className="gap-2 lg:gap-4"          // Smaller → Larger gaps
className="space-y-4 lg:space-y-6"  // Vertical spacing
className="mb-4 lg:mb-6"            // Bottom margin
```

### Responsive Grid
```jsx
className="grid-cols-1 sm:grid-cols-2 lg:grid-cols-4"
// Mobile: 1 column
// Tablet: 2 columns  
// Desktop: 4 columns
```

### Responsive Visibility
```jsx
className="hidden lg:block"         // Hide on mobile, show on desktop
className="lg:hidden"               // Show on mobile, hide on desktop
className="hidden sm:inline"        // Hide on mobile, inline on tablet+
```

### Responsive Layout Direction
```jsx
className="flex-col lg:flex-row"    // Stack on mobile, horizontal on desktop
```

## Testing Checklist

### Mobile (iPhone SE - 375px)
- [ ] Menu opens/closes smoothly
- [ ] No horizontal scrolling
- [ ] All text readable
- [ ] Buttons easily tappable (44px minimum)
- [ ] Forms work correctly

### Tablet (iPad - 768px)
- [ ] Sidebar visible
- [ ] 2-column layouts work
- [ ] Touch targets adequate
- [ ] Content not cramped

### Desktop (1920px)
- [ ] All features visible
- [ ] No wasted space
- [ ] Sidebar expandable
- [ ] Multi-column layouts active

### Landscape Mobile (667px × 375px)
- [ ] Header doesn't take too much vertical space
- [ ] Content area sufficient
- [ ] Navigation accessible

## Performance Tips

1. **Use CSS instead of JavaScript** for responsive behavior
2. **Leverage Tailwind's purge** to remove unused classes
3. **Optimize images** with responsive srcset
4. **Test on real devices** not just browser DevTools
5. **Check touch targets** are at least 44x44px

## Browser DevTools

### Chrome/Edge
```
F12 → Device Toolbar (Ctrl+Shift+M)
Select: iPhone, iPad, or custom dimensions
```

### Firefox
```
F12 → Responsive Design Mode (Ctrl+Shift+M)
Select: iPhone, Galaxy, iPad, or custom
```

### Safari
```
Develop → Enter Responsive Design Mode
Select device from dropdown
```

## Common Mobile Issues Fixed

✅ **Sidebar overflow**: Now hidden on mobile with slide-in drawer
✅ **Text overflow**: Truncated with ellipsis or line-clamp
✅ **Tiny buttons**: Increased touch targets to 44px minimum
✅ **Horizontal scroll**: Removed with overflow-hidden and proper widths
✅ **Unreadable text**: Increased to minimum 12px (text-xs)
✅ **Cramped layout**: Responsive padding and margins
✅ **Hidden content**: Made visible with scroll or collapsible sections
✅ **Fixed headers**: Proper height constraints on mobile
