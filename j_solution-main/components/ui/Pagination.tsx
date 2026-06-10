import React from "react";

interface PaginationProps {
  currentPage: number;
  totalPages: number;
  onPageChange: (page: number) => void;
}

export function Pagination({ currentPage, totalPages, onPageChange }: PaginationProps) {
  if (totalPages <= 1) return null;

  return (
    <div className="flex items-center justify-center gap-1 mt-2 border-t border-border-subtle pt-4">
      <button 
        className="btn-ghost px-2.5 py-1 text-xs disabled:opacity-30 disabled:cursor-not-allowed" 
        disabled={currentPage === 1}
        onClick={() => onPageChange(currentPage - 1)}
      >
        이전
      </button>
      
      {(() => {
        const delta = 2;
        const pages: (number | "...")[] = [];
        const left  = Math.max(2, currentPage - delta);
        const right = Math.min(totalPages - 1, currentPage + delta);

        pages.push(1);
        if (left > 2) pages.push("...");
        for (let p = left; p <= right; p++) pages.push(p);
        if (right < totalPages - 1) pages.push("...");
        if (totalPages > 1) pages.push(totalPages);

        return pages.map((page, i) =>
          page === "..." ? (
            <span key={`ellipsis-${i}`} className="px-1 text-xs text-text-muted">…</span>
          ) : (
            <button
              key={page}
              className={`px-3 py-1.5 text-xs rounded-md transition-colors ${
                currentPage === page
                  ? "bg-accent-blue text-[#0d1117] font-bold"
                  : "text-text-muted hover:text-text-primary hover:bg-bg-hover"
              }`}
              onClick={() => onPageChange(page as number)}
            >
              {page}
            </button>
          )
        );
      })()}

      <button 
        className="btn-ghost px-2.5 py-1 text-xs disabled:opacity-30 disabled:cursor-not-allowed" 
        disabled={currentPage === totalPages}
        onClick={() => onPageChange(currentPage + 1)}
      >
        다음
      </button>
    </div>
  );
}
